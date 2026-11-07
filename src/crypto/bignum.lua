--- @module "crypto.bignum"
--- Arbitrary-precision unsigned integer arithmetic, sized for 3072-bit modular
--- exponentiation (SRP-6a / RFC 5054 group 15).
---
--- The hot path is `mod_exp`, which uses Montgomery multiplication plus a
--- sliding-window exponentiation. See the notes above `mod_exp_montgomery` for
--- why those two were chosen over the naive "square and multiply with a full
--- divmod after every step".
---
--- With `crypto.use_openssl(true)`, `mod_exp` and large `mul`, `divmod`, `mod`
--- and `mod_mul` run through lua-openssl's `bn`, each only after the binding
--- passes a known-answer check for it; see "INTERNAL: OPENSSL ACCELERATION".
---
--- Representation
--- --------------
--- A big number is a plain Lua array of `LIMB_BITS`-bit limbs, least
--- significant first, normalized so that the most significant limb is non-zero.
--- Zero is the empty table. This is the *canonical* representation and the only
--- type any public function ever accepts or returns.
---
--- @class crypto.bignum
local bignum = {}

local openssl_wrapper = require("crypto.openssl_wrapper")

-- Local references for performance
local floor = math.floor
local string_byte = string.byte
local string_char = string.char
local string_find = string.find
local string_format = string.format
local string_rep = string.rep
local string_sub = string.sub
local table_concat = table.concat

-- ============================================================================
-- CONSTANTS
-- ============================================================================

--- @alias BigNum integer[] Little-endian array of 24-bit limbs; {} is zero.
--- @alias BigNumOp "mul"|"divmod"|"mod"|"mod_mul"|"mod_exp" An operation OpenSSL may run.

-- Limb width.
--
-- OVERFLOW BOUND (the whole portability story lives here). On Lua 5.1, 5.2 and
-- LuaJIT every number is an IEEE double, so integers are exact only up to 2^53.
-- A 3072-bit operand is n = 3072/24 = 128 limbs, and a column of a schoolbook
-- multiply accumulates n products each < 2^(2*24), which needs
-- 2*24 + ceil(log2(128)) = 48 + 7 = 55 bits: too wide. So this module never
-- lets a column accumulate. Every multiply-accumulate loop propagates its carry
-- on *every* iteration, which caps the accumulator at
--
--   INVARIANT: t <= (BASE-1) + (BASE-1)^2 + (BASE-1) = BASE^2 - 1 = 2^48 - 1
--
-- independently of the operand length, leaving 5 bits (a factor of 32) of
-- headroom below 2^53. The three shapes that must respect it are `mul_raw`,
-- `mont_mul` and the multiply-subtract step of `divmod_raw`; each carries
-- inline and each is annotated below.
--
-- 24 bits also divides evenly into both bytes (3) and hex digits (6), which
-- removes all cross-boundary bit fiddling from the conversion routines.
local LIMB_BITS = 24
local LIMB_BYTES = 3
local LIMB_HEX = 6
local BASE = 16777216 -- 2^24
local BASE_HALF = 8388608 -- 2^23
--- Exact reciprocal of BASE: a power of two, so `x * INV_BASE` is bit-identical
--- to `x / BASE` for every integer x < 2^53, but avoids a hardware divide in
--- the inner loops.
local INV_BASE = 1 / 16777216

--- Powers of two up to the limb width, for bit extraction without 5.3+ shifts.
local POW2 = {}
for i = 0, LIMB_BITS do
  POW2[i] = 2 ^ i
end

--- Largest Lua number that survives `from_number` exactly on a double-only VM.
local MAX_SAFE_NUMBER = 9007199254740992 -- 2^53

-- Known answers shared by the tests and OPENSSL_CHECKS, computed
-- independently with CPython. Multi-limb so a binding that mis-parses long
-- operands is caught.
local VEC_X_HEX = "f0e1d2c3b4a5968778695a4b3c2d1e0fdeadbeefcafebabe0123456789abcdef"
local VEC_Y_HEX = "fedcba987654321fedcba9876543210abcdef0123456789"
local VEC_M_HEX = "fffffffffffffffffffffffffffffffeffffffffffffffff"
local VEC_MUL_HEX = table_concat({
  "efcfc0c2d5fa2f84db52db751fdba8927fd0cfb89d03a6e23469667bcbb09e04",
  "0c96803be0e492284a6a2290002002425d85431fb375de7",
})
local VEC_QUO_HEX = "f1f51dfdb8e1c16d7"
local VEC_REM_HEX = "4e56a81e2677fc8622ba2a844cc25a8440c2e32a28013e0"
local VEC_MOD_X_HEX = "78695a4b3c2d1e10cf8f91b37fa45145f205182b3e516476"
local VEC_MOD_MUL_HEX = "c5789ec2c73be1123b996b5bf34a44eba5d1145d374fc548"
local VEC_MOD_EXP_HEX = "e6663770f70809f8c052b35cc00534b8d5b2c013a9d4874c"

--- Minimum pure-Lua limb products per limb converted for divmod, mod and mod_mul
--- to route to OpenSSL, and the higher one mul needs; see "INTERNAL: OPENSSL
--- ACCELERATION".
local ROUTE_MIN_RATIO = 4
local MUL_ROUTE_MIN_RATIO = 12

-- ============================================================================
-- INTERNAL: CORE HELPERS
-- ============================================================================

--- Strip high-order zero limbs so the value is canonical.
--- @param t BigNum Limb array, modified in place
--- @return BigNum t The same array, normalized
local function normalize(t)
  local n = #t
  while n > 0 and t[n] == 0 do
    t[n] = nil
    n = n - 1
  end
  return t
end

--- Create a zero-filled limb array of a fixed length.
--- @param n integer Number of limbs
--- @return integer[] limbs
local function zeros(n)
  local t = {}
  for i = 1, n do
    t[i] = 0
  end
  return t
end

--- Copy a big number into a fixed-length limb array, zero-extended.
--- @param a BigNum Source value
--- @param n integer Target limb count (must be >= #a)
--- @return integer[] limbs
local function pad(a, n)
  if #a > n then
    error("bignum: value does not fit in " .. n .. " limbs")
  end
  local t = {}
  for i = 1, n do
    t[i] = a[i] or 0
  end
  return t
end

--- Compare two normalized limb arrays.
--- @param a BigNum First value
--- @param b BigNum Second value
--- @return integer cmp -1 if a < b, 0 if equal, 1 if a > b
local function compare_raw(a, b)
  local na, nb = #a, #b
  if na ~= nb then
    return na < nb and -1 or 1
  end
  for i = na, 1, -1 do
    local ai, bi = a[i], b[i]
    if ai ~= bi then
      return ai < bi and -1 or 1
    end
  end
  return 0
end

--- Add two normalized limb arrays.
--- @param a BigNum First addend
--- @param b BigNum Second addend
--- @return BigNum sum
local function add_raw(a, b)
  local na, nb = #a, #b
  if nb > na then
    -- Keep `a` as the longer operand so the loop below can index `b` sparsely.
    -- `nb` is deliberately not reassigned: it is not read after this point.
    a, b, na = b, a, nb
  end
  local r = {}
  local carry = 0
  for i = 1, na do
    local x = a[i] + (b[i] or 0) + carry
    if x >= BASE then
      r[i] = x - BASE
      carry = 1
    else
      r[i] = x
      carry = 0
    end
  end
  if carry ~= 0 then
    r[na + 1] = carry
  end
  return r
end

--- Subtract b from a, assuming a >= b.
--- @param a BigNum Minuend
--- @param b BigNum Subtrahend (must not exceed a)
--- @return BigNum difference
local function sub_raw(a, b)
  -- The loop reads only #a limbs of b, and with canonical operands a wider b is a larger b.
  if #b > #a then
    error("bignum: subtraction would be negative")
  end
  local r = {}
  local borrow = 0
  local na = #a
  for i = 1, na do
    local x = a[i] - (b[i] or 0) - borrow
    if x < 0 then
      r[i] = x + BASE
      borrow = 1
    else
      r[i] = x
      borrow = 0
    end
  end
  if borrow ~= 0 then
    error("bignum: subtraction would be negative")
  end
  return normalize(r)
end

--- Multiply two normalized limb arrays (schoolbook, operand scanning).
--- The carry is propagated on every inner iteration, so no accumulator ever
--- exceeds BASE^2 - 1 = 2^48 - 1 regardless of operand length.
--- @param a BigNum First factor
--- @param b BigNum Second factor
--- @return BigNum product
local function mul_raw(a, b)
  local na, nb = #a, #b
  if na == 0 or nb == 0 then
    return {}
  end
  local r = zeros(na + nb)
  for i = 1, nb do
    local bi = b[i]
    if bi ~= 0 then
      local carry = 0
      local k = i - 1
      for j = 1, na do
        -- <= (BASE-1) + (BASE-1)^2 + (BASE-1) = BASE^2 - 1
        local x = r[k + j] + a[j] * bi + carry
        carry = floor(x * INV_BASE)
        r[k + j] = x - carry * BASE
      end
      local idx = k + na + 1
      while carry ~= 0 do
        local x = r[idx] + carry
        carry = floor(x * INV_BASE)
        r[idx] = x - carry * BASE
        idx = idx + 1
      end
    end
  end
  return normalize(r)
end

--- Divide by a single-limb divisor.
--- @param a BigNum Dividend
--- @param d integer Divisor, 1 <= d < BASE
--- @return BigNum quotient
--- @return integer remainder
local function divmod_small(a, d)
  local q = {}
  local r = 0
  for i = #a, 1, -1 do
    -- r < d < BASE so x < BASE^2
    local x = r * BASE + a[i]
    local qi = floor(x / d)
    q[i] = qi
    r = x - qi * d
  end
  return normalize(q), r
end

--- Full division with remainder (Knuth algorithm D, base 2^24).
--- @param a BigNum Dividend
--- @param b BigNum Divisor (must be non-zero)
--- @return BigNum quotient
--- @return BigNum remainder
local function divmod_raw(a, b)
  local n = #b
  if n == 0 then
    error("bignum: division by zero")
  end
  if compare_raw(a, b) < 0 then
    local r = {}
    for i = 1, #a do
      r[i] = a[i]
    end
    return {}, r
  end
  if n == 1 then
    local q, r = divmod_small(a, b[1])
    return q, r == 0 and {} or { r }
  end

  -- Normalize so the divisor's top limb is >= BASE/2.
  local shift = 1
  local top = b[n]
  while top < BASE_HALF do
    top = top * 2
    shift = shift * 2
  end

  local v = {}
  local carry = 0
  for i = 1, n do
    local x = b[i] * shift + carry
    carry = floor(x * INV_BASE)
    v[i] = x - carry * BASE
  end

  local m = #a - n
  local u = {}
  carry = 0
  for i = 1, #a do
    local x = a[i] * shift + carry
    carry = floor(x * INV_BASE)
    u[i] = x - carry * BASE
  end
  u[#a + 1] = carry

  local vn, vn1 = v[n], v[n - 1]
  local q = {}
  for j = m, 0, -1 do
    -- num < BASE^2, so the estimate stays exact in a double.
    local num = u[j + n + 1] * BASE + u[j + n]
    local qhat = floor(num / vn)
    local rhat = num - qhat * vn
    if qhat >= BASE then
      qhat = BASE - 1
      rhat = num - qhat * vn
    end
    while rhat < BASE and qhat * vn1 > rhat * BASE + u[j + n - 1] do
      qhat = qhat - 1
      rhat = rhat + vn
    end

    -- Multiply and subtract; borrow carried every iteration keeps p < BASE^2.
    local borrow = 0
    for i = 1, n do
      local p = qhat * v[i] + borrow
      local phigh = floor(p * INV_BASE)
      local x = u[j + i] - (p - phigh * BASE)
      if x < 0 then
        x = x + BASE
        phigh = phigh + 1
      end
      u[j + i] = x
      borrow = phigh
    end
    local x = u[j + n + 1] - borrow
    if x < 0 then
      -- qhat was one too large (probability ~2/BASE); add the divisor back.
      u[j + n + 1] = x + BASE
      qhat = qhat - 1
      local c = 0
      for i = 1, n do
        local y = u[j + i] + v[i] + c
        if y >= BASE then
          u[j + i] = y - BASE
          c = 1
        else
          u[j + i] = y
          c = 0
        end
      end
      u[j + n + 1] = (u[j + n + 1] + c) % BASE
    else
      u[j + n + 1] = x
    end
    q[j + 1] = qhat
  end

  -- Undo the normalization on the remainder.
  local r = {}
  local rem = 0
  for i = n, 1, -1 do
    local x = rem * BASE + u[i]
    local ri = floor(x / shift)
    r[i] = ri
    rem = x - ri * shift
  end

  return normalize(q), normalize(r)
end

--- Read one bit of an exponent, without 5.3+ shift operators.
--- @param e BigNum Value to inspect
--- @param i integer Zero-based bit index
--- @return integer bit 0 or 1
local function get_bit(e, i)
  local limb = e[floor(i / LIMB_BITS) + 1]
  if limb == nil then
    return 0
  end
  return floor(limb / POW2[i % LIMB_BITS]) % 2
end

--- Bit length of a normalized limb array.
--- @param a BigNum Value
--- @return integer bits 0 for zero
local function bit_length_raw(a)
  local n = #a
  if n == 0 then
    return 0
  end
  local bits = (n - 1) * LIMB_BITS
  local top = a[n]
  while top > 0 do
    bits = bits + 1
    top = floor(top / 2)
  end
  return bits
end

-- ============================================================================
-- INTERNAL: MONTGOMERY ARITHMETIC
-- ============================================================================

--- Modular inverse of an odd limb modulo BASE, by Newton iteration.
--- Every step is reduced mod BASE so no intermediate exceeds BASE^2.
--- @param m0 integer Odd value, 1 <= m0 < BASE
--- @return integer n0 (-m0^-1) mod BASE
local function mont_n0(m0)
  local inv = 1
  -- Each round doubles the number of correct bits: 1 -> 2 -> 4 -> 8 -> 16 -> 32.
  for _ = 1, 5 do
    local t = (m0 * inv) % BASE
    t = (2 - t) % BASE
    inv = (inv * t) % BASE
  end
  if (m0 * inv) % BASE ~= 1 then
    error("bignum: modulus is not odd")
  end
  return (BASE - inv) % BASE
end

--- Build the Montgomery context for an odd modulus > 1.
---
--- The context uses one limb more than the modulus needs (`s = #m + 1`) so that
--- 4*m < BASE^s always holds. That is the precondition under which CIOS output
--- stays below 2*m and a single conditional subtraction suffices; without the
--- spare limb a 3072-bit modulus (which is *exactly* 128 limbs wide) would
--- overflow the accumulator's top word.
---
--- @param m BigNum Odd modulus, m > 1
--- @return table ctx Fields: s, mp, n0, r1 (R mod m), r2 (R^2 mod m)
local function mont_context(m)
  local s = #m + 1
  local mp = pad(m, s)
  local n0 = mont_n0(mp[1])

  -- R = BASE^s
  local r = zeros(s + 1)
  r[s + 1] = 1
  local _, r1 = divmod_raw(normalize(r), m)
  local _, r2 = divmod_raw(mul_raw(r1, r1), m)

  return { s = s, mp = mp, n0 = n0, r1 = pad(r1, s), r2 = pad(r2, s), t = zeros(s + 2) }
end

--- Montgomery multiplication: out = a * b * R^-1 mod m (CIOS).
---
--- `out` may alias `a` or `b`: every read of the operands happens before the
--- single write-back at the end.
---
--- @param ctx table Context from `mont_context`
--- @param a integer[] Left operand, exactly ctx.s limbs
--- @param b integer[] Right operand, exactly ctx.s limbs
--- @param out integer[] Destination, exactly ctx.s limbs
--- @return integer[] out
local function mont_mul(ctx, a, b, out)
  local s = ctx.s
  local mp = ctx.mp
  local n0 = ctx.n0
  local t = ctx.t

  for i = 1, s + 2 do
    t[i] = 0
  end

  for i = 1, s do
    local bi = b[i]
    local c = 0
    for j = 1, s do
      -- <= (BASE-1) + (BASE-1)^2 + (BASE-1) = BASE^2 - 1 = 2^48 - 1
      local x = t[j] + a[j] * bi + c
      c = floor(x * INV_BASE)
      t[j] = x - c * BASE
    end
    local x = t[s + 1] + c
    c = floor(x * INV_BASE)
    t[s + 1] = x - c * BASE
    t[s + 2] = c

    local mi = (t[1] * n0) % BASE
    -- t[1] + mi*mp[1] is a multiple of BASE by construction of n0.
    x = t[1] + mi * mp[1]
    c = floor(x * INV_BASE)
    for j = 2, s do
      x = t[j] + mi * mp[j] + c
      c = floor(x * INV_BASE)
      t[j - 1] = x - c * BASE
    end
    x = t[s + 1] + c
    c = floor(x * INV_BASE)
    t[s] = x - c * BASE
    t[s + 1] = t[s + 2] + c
  end

  -- Result is < 2*m: one conditional subtraction brings it into range.
  local subtract = t[s + 1] ~= 0
  if not subtract then
    local cmp = 0 -- 0 means "equal to m so far", so subtract
    for j = s, 1, -1 do
      local tv, mv = t[j], mp[j]
      if tv ~= mv then
        cmp = tv > mv and 1 or -1
        break
      end
    end
    subtract = cmp >= 0
  end

  if subtract then
    local borrow = 0
    for j = 1, s do
      local x = t[j] - mp[j] - borrow
      if x < 0 then
        out[j] = x + BASE
        borrow = 1
      else
        out[j] = x
        borrow = 0
      end
    end
  else
    for j = 1, s do
      out[j] = t[j]
    end
  end
  return out
end

--- Pick a sliding-window width for an exponent of the given bit length.
--- @param bits integer Exponent bit length
--- @return integer w Window width
local function window_width(bits)
  if bits <= 23 then
    return 1
  elseif bits <= 79 then
    return 3
  elseif bits <= 239 then
    return 4
  end
  return 5
end

--- Modular exponentiation via Montgomery multiplication + sliding window.
---
--- Why: the textbook "square and multiply, then divmod" costs a full Knuth
--- division per step, and division is several times more expensive than the
--- multiplication it reduces. Montgomery replaces every reduction with a second
--- multiply-accumulate pass over the same limbs, so a modular square costs
--- 2*s^2 limb products and no division at all. On top of that a sliding window
--- of width w replaces ~bits/2 multiplications with ~bits/(w+1) of them: for a
--- 3072-bit exponent that is roughly 3072 squarings + ~512 multiplications
--- instead of 3072 + ~1536.
---
--- Requires an odd modulus greater than 1, which the RFC 5054 safe primes are.
---
--- @param base BigNum Base
--- @param exp BigNum Exponent, must be non-zero
--- @param m BigNum Odd modulus, m > 1
--- @return BigNum result base^exp mod m
local function mod_exp_montgomery(base, exp, m)
  local ctx = mont_context(m)
  local s = ctx.s

  local _, reduced = divmod_raw(base, m)
  local x = pad(reduced, s)
  mont_mul(ctx, x, ctx.r2, x) -- x -> Montgomery form

  local bits = bit_length_raw(exp)
  local w = window_width(bits)

  -- Odd powers x^1, x^3, ... x^(2^w - 1), all in Montgomery form.
  local odd = { [1] = x }
  if w > 1 then
    local x2 = mont_mul(ctx, x, x, zeros(s))
    for k = 3, POW2[w] - 1, 2 do
      odd[k] = mont_mul(ctx, odd[k - 2], x2, zeros(s))
    end
  end

  local acc = pad(ctx.r1, s) -- Montgomery representation of 1
  local i = bits - 1
  while i >= 0 do
    if get_bit(exp, i) == 0 then
      mont_mul(ctx, acc, acc, acc)
      i = i - 1
    else
      local l = i - w + 1
      if l < 0 then
        l = 0
      end
      while get_bit(exp, l) == 0 do
        l = l + 1
      end
      local value = 0
      for k = i, l, -1 do
        value = value * 2 + get_bit(exp, k)
      end
      for _ = 1, i - l + 1 do
        mont_mul(ctx, acc, acc, acc)
      end
      mont_mul(ctx, acc, odd[value], acc)
      i = l - 1
    end
  end

  -- Leave the Montgomery domain: acc * 1 * R^-1.
  local one = zeros(s)
  one[1] = 1
  mont_mul(ctx, acc, one, acc)
  return normalize(acc)
end

--- Slow, obvious reference exponentiation: bitwise square-and-multiply with a
--- full division after every step. Kept as the correctness oracle that
--- the tests cross-check the Montgomery path against, and as the fallback
--- for the even moduli Montgomery cannot handle.
--- @param base BigNum Base
--- @param exp BigNum Exponent
--- @param m BigNum Modulus, m > 0
--- @return BigNum result base^exp mod m
local function mod_exp_reference(base, exp, m)
  local _, result = divmod_raw({ 1 }, m)
  local _, b = divmod_raw(base, m)
  for i = bit_length_raw(exp) - 1, 0, -1 do
    local _, sq = divmod_raw(mul_raw(result, result), m)
    result = sq
    if get_bit(exp, i) == 1 then
      local _, pr = divmod_raw(mul_raw(result, b), m)
      result = pr
    end
  end
  return result
end

-- ============================================================================
-- INTERNAL: OPENSSL ACCELERATION
-- ============================================================================

-- The canonical representation is ALWAYS the pure-Lua limb table. OpenSSL is
-- used only as an internal accelerator inside individual operations: operands
-- are converted into openssl.bn handles (big-endian bytes in via bn.text), the
-- operation runs there, and the result is converted straight back to a limb
-- table (hex out via bn.tohex). That is exactly the conversion path Feature.BN
-- probes.
--
-- Rationale: crypto.use_openssl() can be toggled at runtime, so if handles were
-- sometimes userdata and sometimes tables, a toggle mid-flight would produce
-- mixed-type operands and silent breakage. Keeping one canonical type makes the
-- accelerator invisible to callers -- results are identical with and without
-- it, and the tests assert exactly that.
--
-- Conversion runs in Lua and is linear in the limbs moved, while the pure-Lua
-- cost is the schoolbook limb products, so an operation routes only once its
-- estimated work per limb converted reaches a ratio. Linear-cost calls (a
-- one-limb factor or divisor, a narrow quotient, reduced operands, add, sub)
-- stay here at any width. mod_exp routes at every size.
--
-- The ratios were measured on a Control4 controller (arm64, LuaJIT 2.1,
-- lua-openssl 0.8.5, 2026-10-18) with the JIT on, the case that favours pure
-- Lua most: divmod, mod and mod_mul win from 4, mul only from 12 (48x48 limbs
-- 0.94x, 64x64 1.30x, 128x128 2.39x). Without the JIT mul wins from about 3, so
-- there 12 gives up at most a few tenths of a millisecond per multiply.

--- Binding whose behaviour has been checked, and the verdict per operation.
--- @type table?
local _verified_binding = nil
--- @type table<BigNumOp, boolean>
local _verified_ops = {}

--- Estimated pure-Lua cost of a schoolbook division, in limb products.
--- @param na integer Limbs in the dividend
--- @param nb integer Limbs in the divisor
--- @return integer work
local function div_work(na, nb)
  if na < nb then
    return 0
  end
  return (na - nb + 1) * nb
end

--- Whether an operation is worth sending through the binding.
--- @param work integer Estimated pure-Lua cost, in limb products
--- @param limbs_in integer Limbs converted into the binding (the operands)
--- @param limbs_out integer Most limbs converted back out (the results)
--- @param ratio integer Minimum limb products per limb converted
--- @return boolean
local function worth_routing(work, limbs_in, limbs_out, ratio)
  return work > 0 and work >= ratio * (limbs_in + limbs_out)
end

--- Resolve this build's modular-exponentiation entry point.
--- Control4's lua-openssl 0.8.5 spells it `powmod`; other builds use `mod_exp`.
--- @param bnlib table The openssl.bn table
--- @return function powmod
local function bn_powmod(bnlib)
  if type(bnlib.powmod) == "function" then
    return bnlib.powmod
  end
  return bnlib.mod_exp
end

--- Build an openssl.bn handle from a canonical big number.
--- `bn.text` takes big-endian bytes; zero is passed as a single zero byte
--- rather than the empty string, which not every build accepts.
--- @param bnlib table The openssl.bn table
--- @param value BigNum Value to convert
--- @return any handle Opaque openssl.bn value
local function bn_from_bignum(bnlib, value)
  if #value == 0 then
    return bnlib.text("\0")
  end
  return bnlib.text(bignum.to_bytes(value))
end

--- Convert an openssl.bn handle back into a canonical big number. Only bare hex
--- digits are accepted: `bn.tohex` signs negatives with "-", which `from_hex`
--- would read as a negative limb instead of rejecting.
--- @param bnlib table The openssl.bn table
--- @param handle any Opaque openssl.bn value
--- @return BigNum value
local function bignum_from_bn(bnlib, handle)
  local hex = bnlib.tohex(handle)
  if type(hex) ~= "string" or string_find(hex, "^%x+$") == nil then
    error("bignum: openssl bn.tohex did not return unsigned hex")
  end
  return bignum.from_hex(hex)
end

--- Refuse a zero divisor, which the binding answers with 0 instead of raising
--- (lua-openssl 0.8.5, 0.9.2 and 0.11.1, measured 2026-10-17). The raise sends
--- the call back to pure Lua, which reports the real error.
--- @param m BigNum Divisor or modulus
local function require_nonzero(m)
  if #m == 0 then
    error("bignum: zero divisor")
  end
end

--- Each routed operation as run through the binding; anything unexpected raises.
--- @type table<BigNumOp, fun(bnlib: table, a: BigNum, b: BigNum, c: BigNum?): BigNum, BigNum?>
local OPENSSL_OPS = {
  mul = function(bnlib, a, b)
    return bignum_from_bn(bnlib, bnlib.mul(bn_from_bignum(bnlib, a), bn_from_bignum(bnlib, b)))
  end,
  divmod = function(bnlib, a, b)
    require_nonzero(b)
    local quotient, remainder = bnlib.divmod(bn_from_bignum(bnlib, a), bn_from_bignum(bnlib, b))
    return bignum_from_bn(bnlib, quotient), bignum_from_bn(bnlib, remainder)
  end,
  mod = function(bnlib, a, m)
    require_nonzero(m)
    return bignum_from_bn(bnlib, bnlib.mod(bn_from_bignum(bnlib, a), bn_from_bignum(bnlib, m)))
  end,
  mod_mul = function(bnlib, a, b, m)
    --- @cast m BigNum
    require_nonzero(m)
    local product = bnlib.mulmod(bn_from_bignum(bnlib, a), bn_from_bignum(bnlib, b), bn_from_bignum(bnlib, m))
    return bignum_from_bn(bnlib, product)
  end,
  mod_exp = function(bnlib, base, exp, m)
    --- @cast m BigNum
    require_nonzero(m)
    local result = bn_powmod(bnlib)(bn_from_bignum(bnlib, base), bn_from_bignum(bnlib, exp), bn_from_bignum(bnlib, m))
    return bignum_from_bn(bnlib, result)
  end,
}

--- One multi-limb known answer per routed operation, as hex. `Feature.BN` only
--- round-trips a single-digit powmod, so it proves neither that long operands
--- parse nor that mul, divmod, mod and mulmod work. Each is checked on its own
--- so one broken entry point does not take mod_exp down with it.
--- @type table<BigNumOp, { args: string[], results: string[] }>
local OPENSSL_CHECKS = {
  mul = { args = { VEC_X_HEX, VEC_Y_HEX }, results = { VEC_MUL_HEX } },
  divmod = { args = { VEC_X_HEX, VEC_Y_HEX }, results = { VEC_QUO_HEX, VEC_REM_HEX } },
  mod = { args = { VEC_X_HEX, VEC_M_HEX }, results = { VEC_MOD_X_HEX } },
  mod_mul = { args = { VEC_X_HEX, VEC_Y_HEX, VEC_M_HEX }, results = { VEC_MOD_MUL_HEX } },
  mod_exp = { args = { VEC_X_HEX, VEC_Y_HEX, VEC_M_HEX }, results = { VEC_MOD_EXP_HEX } },
}

--- Run one operation through a binding, turning any failure into nil. The
--- known-answer check comes through here too, so it tests the exact call trusted.
--- @param bnlib table The openssl.bn table
--- @param op BigNumOp Operation to run
--- @param a BigNum First operand
--- @param b BigNum Second operand
--- @param c? BigNum Third operand
--- @return BigNum|nil first Result, or nil on any failure
--- @return BigNum|nil second Second result (divmod's remainder)
local function call_binding(bnlib, op, a, b, c)
  local ok, first, second = pcall(OPENSSL_OPS[op], bnlib, a, b, c)
  if not ok then
    return nil, nil
  end
  return first, second
end

--- Run one operation's known answer through a binding.
--- @param bnlib table The openssl.bn table
--- @param op BigNumOp Operation to check
--- @return boolean passed
local function passes_check(bnlib, op)
  local check = OPENSSL_CHECKS[op]
  local args = {}
  for i, hex in ipairs(check.args) do
    args[i] = bignum.from_hex(hex)
  end
  local got = { call_binding(bnlib, op, args[1], args[2], args[3]) }
  for i, hex in ipairs(check.results) do
    if type(got[i]) ~= "table" or compare_raw(got[i], bignum.from_hex(hex)) ~= 0 then
      return false
    end
  end
  return true
end

--- The openssl.bn table if `op` should run there, nil otherwise: needs
--- `Feature.BN` and `op`'s known-answer check, run once per binding and cached.
--- @param op BigNumOp Operation to ask about
--- @return table|nil bnlib
local function trusted_bn(op)
  local openssl = openssl_wrapper.get(openssl_wrapper.Feature.BN)
  if openssl == nil then
    return nil
  end
  if _verified_binding ~= openssl then
    _verified_binding = openssl
    _verified_ops = {}
  end
  local verdict = _verified_ops[op]
  if verdict == nil then
    verdict = passes_check(openssl.bn, op)
    _verified_ops[op] = verdict
  end
  if verdict then
    return openssl.bn
  end
  return nil
end

--- Run `op` through OpenSSL when that is enabled and trusted.
--- @param op BigNumOp Operation to run
--- @param a BigNum First operand
--- @param b BigNum Second operand
--- @param c? BigNum Third operand
--- @return BigNum|nil first Result, or nil when the caller must use pure Lua
--- @return BigNum|nil second Second result (divmod's remainder)
local function run_openssl(op, a, b, c)
  local bnlib = trusted_bn(op)
  if bnlib == nil then
    return nil, nil
  end
  return call_binding(bnlib, op, a, b, c)
end

-- ============================================================================
-- PUBLIC INTERFACE: CONSTRUCTION AND CONVERSION
-- ============================================================================

--- Create a big number from a big-endian byte string of any length.
--- @param str string Big-endian bytes ("" is zero)
--- @return BigNum bn
function bignum.from_bytes(str)
  local n = #str
  local r = {}
  local k = 0
  local i = n
  while i >= 1 do
    local b0 = string_byte(str, i)
    local b1 = i >= 2 and string_byte(str, i - 1) or 0
    local b2 = i >= 3 and string_byte(str, i - 2) or 0
    k = k + 1
    r[k] = b0 + b1 * 256 + b2 * 65536
    i = i - LIMB_BYTES
  end
  return normalize(r)
end

--- Serialize a big number to big-endian bytes.
--- Without `length` the encoding is minimal, so zero serializes to "" and
--- `from_bytes(to_bytes(x)) == x` for every x. With `length` the result is
--- left-padded with zero bytes to exactly that many bytes, which is what SRP
--- needs when hashing values modulo N.
--- @param bn BigNum Value
--- @param length? integer Exact output length in bytes
--- @return string str Big-endian bytes
function bignum.to_bytes(bn, length)
  local parts = {}
  for k = #bn, 1, -1 do
    local v = bn[k]
    local b2 = floor(v / 65536)
    parts[#parts + 1] = string_char(b2, floor(v / 256) % 256, v % 256)
  end
  local raw = table_concat(parts)
  local first = 1
  local total = #raw
  while first <= total and string_byte(raw, first) == 0 do
    first = first + 1
  end
  local trimmed = string_sub(raw, first)
  if length == nil then
    return trimmed
  end
  if #trimmed > length then
    error("bignum: value needs " .. #trimmed .. " bytes, cannot fit in " .. length)
  end
  return string_rep("\0", length - #trimmed) .. trimmed
end

--- Parse a hexadecimal string (either case, any length, no prefix).
--- @param hex string Hex digits ("" or "0" is zero)
--- @return BigNum bn
function bignum.from_hex(hex)
  local r = {}
  local k = 0
  local i = #hex
  while i >= 1 do
    local j = i - LIMB_HEX + 1
    if j < 1 then
      j = 1
    end
    local chunk = string_sub(hex, j, i)
    local value = tonumber(chunk, 16)
    if value == nil then
      error("bignum: invalid hex digits '" .. chunk .. "'")
    end
    k = k + 1
    r[k] = value
    i = j - 1
  end
  return normalize(r)
end

--- Serialize to lowercase hex with no leading zeros ("0" for zero).
--- @param bn BigNum Value
--- @return string hex
function bignum.to_hex(bn)
  local n = #bn
  if n == 0 then
    return "0"
  end
  local parts = { string_format("%x", bn[n]) }
  for k = n - 1, 1, -1 do
    parts[#parts + 1] = string_format("%06x", bn[k])
  end
  return table_concat(parts)
end

--- Create a big number from a non-negative Lua integer.
--- @param n integer Value in [0, 2^53]
--- @return BigNum bn
function bignum.from_number(n)
  if type(n) ~= "number" or n < 0 or n ~= floor(n) then
    error("bignum: from_number requires a non-negative integer")
  end
  if n > MAX_SAFE_NUMBER then
    error("bignum: from_number is limited to 2^53; use from_hex or from_bytes")
  end
  local r = {}
  local k = 0
  while n > 0 do
    k = k + 1
    r[k] = n % BASE
    n = floor(n / BASE)
  end
  return r
end

--- The value zero.
--- @return BigNum bn
function bignum.zero()
  return {}
end

--- The value one.
--- @return BigNum bn
function bignum.one()
  return { 1 }
end

--- Duplicate a big number; the copy shares no state with the original.
--- @param bn BigNum Value
--- @return BigNum copy
function bignum.copy(bn)
  local r = {}
  for i = 1, #bn do
    r[i] = bn[i]
  end
  return r
end

-- ============================================================================
-- PUBLIC INTERFACE: INSPECTION
-- ============================================================================

--- Test whether a value is zero.
--- @param bn BigNum Value
--- @return boolean is_zero
function bignum.is_zero(bn)
  return #bn == 0
end

--- Number of significant bits (0 for zero).
--- @param bn BigNum Value
--- @return integer bits
function bignum.bit_length(bn)
  return bit_length_raw(bn)
end

--- Number of bytes in the minimal big-endian encoding (0 for zero).
--- @param bn BigNum Value
--- @return integer count
function bignum.byte_length(bn)
  local bits = bit_length_raw(bn)
  return floor((bits + 7) / 8)
end

--- Three-way comparison.
--- @param a BigNum First value
--- @param b BigNum Second value
--- @return integer cmp -1 if a < b, 0 if a == b, 1 if a > b
function bignum.compare(a, b)
  return compare_raw(a, b)
end

--- Equality test.
--- @param a BigNum First value
--- @param b BigNum Second value
--- @return boolean equal
function bignum.equals(a, b)
  return compare_raw(a, b) == 0
end

-- ============================================================================
-- PUBLIC INTERFACE: ARITHMETIC
-- ============================================================================

--- Addition.
--- @param a BigNum First addend
--- @param b BigNum Second addend
--- @return BigNum sum
function bignum.add(a, b)
  return add_raw(a, b)
end

--- Subtraction. Errors when b > a, since values are unsigned.
--- @param a BigNum Minuend
--- @param b BigNum Subtrahend
--- @return BigNum difference
function bignum.sub(a, b)
  return sub_raw(a, b)
end

--- Multiplication. Large operands run through OpenSSL when it is enabled.
--- @param a BigNum First factor
--- @param b BigNum Second factor
--- @return BigNum product
function bignum.mul(a, b)
  if worth_routing(#a * #b, #a + #b, #a + #b, MUL_ROUTE_MIN_RATIO) then
    local product = run_openssl("mul", a, b)
    if product then
      return product
    end
  end
  return mul_raw(a, b)
end

--- Division with remainder. Large quotients run through OpenSSL when enabled.
--- @param a BigNum Dividend
--- @param b BigNum Divisor (must be non-zero)
--- @return BigNum quotient floor(a / b)
--- @return BigNum remainder a - quotient * b
function bignum.divmod(a, b)
  -- Out: a quotient of up to #a - #b + 1 limbs and a remainder of up to #b.
  if worth_routing(div_work(#a, #b), #a + #b, #a + 1, ROUTE_MIN_RATIO) then
    local quotient, remainder = run_openssl("divmod", a, b)
    if quotient and remainder then
      return quotient, remainder
    end
  end
  return divmod_raw(a, b)
end

--- Remainder of a divided by b. Large quotients run through OpenSSL when enabled.
--- @param a BigNum Dividend
--- @param b BigNum Modulus (must be non-zero)
--- @return BigNum remainder
function bignum.mod(a, b)
  if worth_routing(div_work(#a, #b), #a + #b, #b, ROUTE_MIN_RATIO) then
    local remainder = run_openssl("mod", a, b)
    if remainder then
      return remainder
    end
  end
  local _, r = divmod_raw(a, b)
  return r
end

--- Modular addition.
--- @param a BigNum First addend
--- @param b BigNum Second addend
--- @param m BigNum Modulus (must be non-zero)
--- @return BigNum result (a + b) mod m
function bignum.mod_add(a, b, m)
  return bignum.mod(add_raw(a, b), m)
end

--- Modular subtraction, always returning a non-negative residue.
--- SRP computes B - k*g^x, where the subtraction can go negative, so this wraps
--- rather than erroring.
--- @param a BigNum Minuend
--- @param b BigNum Subtrahend
--- @param m BigNum Modulus (must be non-zero)
--- @return BigNum result (a - b) mod m
function bignum.mod_sub(a, b, m)
  local ra = bignum.mod(a, m)
  local rb = bignum.mod(b, m)
  if compare_raw(ra, rb) >= 0 then
    return sub_raw(ra, rb)
  end
  return sub_raw(add_raw(ra, m), rb)
end

--- Modular multiplication. Large operands run through OpenSSL when enabled.
--- @param a BigNum First factor
--- @param b BigNum Second factor
--- @param m BigNum Modulus (must be non-zero)
--- @return BigNum result (a * b) mod m
function bignum.mod_mul(a, b, m)
  local product_limbs = (#a == 0 or #b == 0) and 0 or #a + #b
  if worth_routing(#a * #b + div_work(product_limbs, #m), #a + #b + #m, #m, ROUTE_MIN_RATIO) then
    local result = run_openssl("mod_mul", a, b, m)
    if result then
      return result
    end
  end
  local _, r = divmod_raw(mul_raw(a, b), m)
  return r
end

--- Modular exponentiation -- the hot path for SRP-6a.
---
--- Dispatch order: a verified OpenSSL binding if acceleration is enabled (at
--- any operand size), otherwise Montgomery + sliding window for odd moduli,
--- otherwise the slow reference path. All three return identical values.
---
--- @param base BigNum Base
--- @param exp BigNum Exponent
--- @param m BigNum Modulus (must be non-zero)
--- @return BigNum result base^exp mod m
function bignum.mod_exp(base, exp, m)
  if #m == 0 then
    error("bignum: mod_exp modulus must be non-zero")
  end
  if #m == 1 and m[1] == 1 then
    return {}
  end
  if #exp == 0 then
    return { 1 }
  end

  local result = run_openssl("mod_exp", base, exp, m)
  if result then
    return result
  end

  if m[1] % 2 == 1 then
    return mod_exp_montgomery(base, exp, m)
  end
  -- Montgomery needs an odd modulus; even moduli are not used by SRP.
  return mod_exp_reference(base, exp, m)
end

--- Whether an operation will use the OpenSSL backend; `mod_exp` by default.
---
--- Answers the question callers actually have -- "will a 3072-bit exponentiation
--- finish in milliseconds or in minutes?" -- so it applies the same two
--- conditions the operation does: acceleration enabled with a binding that
--- passes `Feature.BN`, *and* a binding that reproduces that operation's
--- multi-limb known-answer vector. Checking the feature gate alone would report
--- true for a binding this module has already decided not to trust.
---
--- Each operation is checked separately, so the answers can differ. For mul,
--- divmod, mod and mod_mul, true covers only calls wide enough to route. Losing
--- one of those costs milliseconds per 3072-bit call; losing mod_exp costs
--- seconds, which is why `srp.is_accelerated` asks about it alone.
---
--- The verdict is not static: it changes with `crypto.use_openssl()`.
---
--- A false verdict comes with the reason, because the two common causes need
--- opposite responses and are otherwise indistinguishable: a host that cannot
--- accelerate has to be designed around, while a caller that never enabled
--- acceleration just has to make one call. The reason is always present when
--- `accelerated` is false.
---
--- @param op? BigNumOp Operation to ask about; "mod_exp" when omitted
--- @return boolean accelerated True if OpenSSL will handle the operation
--- @return string|nil reason Why it will not, when it will not
function bignum.is_accelerated(op)
  op = op or "mod_exp"
  if OPENSSL_OPS[op] == nil then
    error("bignum: unknown operation '" .. tostring(op) .. "'")
  end
  local openssl = openssl_wrapper.get(openssl_wrapper.Feature.BN)
  if openssl == nil then
    return false,
      openssl_wrapper.unavailable_reason(openssl_wrapper.Feature.BN) or "OpenSSL modular exponentiation is unavailable"
  end
  if trusted_bn(op) == nil then
    return false,
      "the lua-openssl binding failed bignum's multi-limb known-answer check, so it is not trusted for "
        .. (op == "mod_exp" and "modular exponentiation" or op)
  end
  return true
end

-- Private functions and values the tests in test/ check directly.
bignum._internal = {
  add_raw = add_raw,
  mul_raw = mul_raw,
  divmod_raw = divmod_raw,
  mod_exp_montgomery = mod_exp_montgomery,
  mod_exp_reference = mod_exp_reference,
}

return bignum
