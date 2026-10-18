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

local utils = require("crypto.utils")
local bytes = utils.bytes
local benchmark_op = utils.benchmark.benchmark_op
local openssl_wrapper = require("crypto.openssl_wrapper")

-- Local references for performance
local floor = math.floor
local string_byte = string.byte
local string_char = string.char
local string_find = string.find
local string_format = string.format
local string_rep = string.rep
local string_sub = string.sub
local string_upper = string.upper
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

-- Known answers shared by `selftest()` and OPENSSL_CHECKS, computed
-- independently with CPython. Multi-limb so a binding that mis-parses long
-- operands is caught.
local VEC_X_HEX = "f0e1d2c3b4a5968778695a4b3c2d1e0fdeadbeefcafebabe0123456789abcdef"
local VEC_Y_HEX = "fedcba987654321fedcba9876543210abcdef0123456789"
local VEC_M_HEX = "fffffffffffffffffffffffffffffffeffffffffffffffff"
local VEC_ADD_HEX = "f0e1d2c3b4a59687885725f4c3926131dd8a79884152ecceacf13468acf13578"
local VEC_SUB_HEX = "f0e1d2c3b4a59687687b8ea1b4c7daeddfd1045754aa88ad5555566666666666"
local VEC_MUL_HEX = table_concat({
  "efcfc0c2d5fa2f84db52db751fdba8927fd0cfb89d03a6e23469667bcbb09e04",
  "0c96803be0e492284a6a2290002002425d85431fb375de7",
})
local VEC_QUO_HEX = "f1f51dfdb8e1c16d7"
local VEC_REM_HEX = "4e56a81e2677fc8622ba2a844cc25a8440c2e32a28013e0"
local VEC_MOD_X_HEX = "78695a4b3c2d1e10cf8f91b37fa45145f205182b3e516476"
local VEC_MOD_ADD_HEX = "885725f4c3926132ce6c4c4bf5f883569dd3072c6196cbff"
local VEC_MOD_SUB_HEX = "9784715e4b3825112f4d28e4f6afe0c9b9c8d6d5e4f40312"
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
--- `selftest()` cross-checks the Montgomery path against, and as the fallback
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
-- it, and selftest() asserts exactly that.
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

-- ============================================================================
-- TEST VECTORS AND VALIDATION
-- ============================================================================

-- Every expected value below was produced independently with CPython's
-- arbitrary-precision integers (`python3 -c "print(pow(g, x, N))"` and friends)
-- and committed here as a literal.

--- RFC 5054 Appendix A / RFC 3526 group 15: the 3072-bit safe prime N.
--- Its generator is g = 5.
local RFC5054_N_HEX = table.concat({
  "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74",
  "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437",
  "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed",
  "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05",
  "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb",
  "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b",
  "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718",
  "3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33",
  "a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7",
  "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864",
  "d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2",
  "08e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff",
})
local SRP_EXP_A_HEX = "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393"
local SRP_RESULT_A_HEX = table.concat({
  "fab6f5d2615d1e323512e7991cc37443f487da604ca8c9230fcb04e541dce628",
  "0b27ca4680b0374f179dc3bdc7553fe62459798c701ad864a91390a28c93b644",
  "adbf9c00745b942b79f9012a21b9b78782319d83a1f8362866fbd6f46bfc0ddb",
  "2e1ab6e4b45a9906b82e37f05d6f97f6a3eb6e182079759c4f6847837b62321a",
  "c1b4fa68641fcb4bb98dd697a0c73641385f4bab25b793584cc39fc8d48d4bd8",
  "67a9a3c10f8ea12170268e34fe3bbe6ff89998d60da2f3e4283cbec1393d52af",
  "724a57230c604e9fbce583d7613e6bffd67596ad121a8707eec4694495703368",
  "6a155f644d5c5863b48f61bdbf19a53eab6dad0a186b8c152e5f5d8cad4b0ef8",
  "aa4ea5008834c3cd342e5e0f167ad04592cd8bd279639398ef9e114dfaaab919",
  "e14e850989224ddd98576d79385d2210902e9f9b1f2d86cfa47ee244635465f7",
  "1058421a0184be51dd10cc9d079e6f1604e7aa9b7cf7883c7d4ce12b06ebe160",
  "81e23f27a231d18432d7d1bb55c28ae21ffcf005f57528d15a88881bb3bbb7fe",
})
local SRP_EXP_B_HEX = table.concat({
  "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
  "3fbb0e0e1e0b1a1c9d8e7f60514243342a1b0c9f8e7d6c5b4a39281706f5e4d3",
  "c2b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a3928170615243f",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a3928170615243f",
})
local SRP_RESULT_B_HEX = table.concat({
  "1e9606e73774d51f84e1eefb8e8ce7b07a0e204b76dc57d55968d4159a32f760",
  "4e36da94747fc9f995e920741169aa810cc25e4a4b7df654bb8e48275e063d6c",
  "744f1e3bfcd18b84e97a69d39ac775b466cc1b0928f0ee55d79e05329a942ca6",
  "af50f660d4af6129e9e378119843836ea8b7c0aa1035d6e33ebf3defd0512ebf",
  "c6dbb3e111a8630cf6d444e98e23fd5219747dcc537da5742fe3b3262a61e6b4",
  "6fa328d398d104bc3735f5e0f883b4c8fe1b3ee5b77ba2222b9b4cff974e060d",
  "9b52bc56a4edaf6b88a149b06eace7a40f68348fd84a28c95a524da2846cd738",
  "4ce58188f44f27c279b5e1279754d82794a67db88ed67a44eddb189094f7830d",
  "4748cecd898d44387558e41293561752775c44360fc5b57fa386470b2019da88",
  "0637a5443c2165f23b2f914b33b601edc8e2aff5dd916387e4c186d495a790da",
  "5f4b2e82b2a881479a4c819086e5fd284fe5144c2cc259d7b5c5c085430268ea",
  "664826f9fdb4e4183b8613b772c50a56a97f1a13c0471d562151b41fcfbd3559",
})
local SRP_BASE_OVER_N_HEX = table.concat({
  "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74",
  "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437",
  "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed",
  "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05",
  "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb",
  "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b",
  "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718",
  "3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33",
  "a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7",
  "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864",
  "d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2",
  "08e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2cb0000000000000006",
})
local SRP_RESULT_OVER_HEX = table.concat({
  "34fd4d3beb508957d7a1b34394835595739fcebae187bc7cf18d8dbee1f8cdd7",
  "fbb20f4d870b7f9f9d13dad25006445975cf81c4fffa0bd26bb399c2b235657c",
  "a7aae7ac6bc6a78cba6ddfd1cc971505b6acbdbbadf8c8346006590588209cbe",
  "3b21c7141166f53da71b9d739c785aa1c722ff5ad6bf0d8556e1836570c3e62d",
  "b1fe8c715b84867c31faa7621b315130de124f38b250052217658a2535e0ca89",
  "014101aec9e8ca705a37b8956dc5a629f80a542c4f02e01150ddd44228c76ab6",
  "77e930f3875e57c5cf87a3ac3b16f94ed2427aa5c4028cb5b7dfd568057f1285",
  "46a28a0cdbf79120c2a955956c7f4ad6220929ae1f76954d347de3bd57d05e31",
  "ca711fa27ab77fc85473d4ba7e89dcca338a0e5c06009edeb5788cc9bc840add",
  "6f3f740da521f6b3be5a1ac0e4d1b8acb500ebe95c99cf713b972ee1f6e4bf29",
  "af7c5f4b88d5893f2deab5df5cb6e7e3ab516d388a9bcdfda0867b6bc93197b9",
  "519e5b25ffa39abb52b18dc6e7e78f601443ae575f1bc59ffc2d86a06af4cf04",
})
local CROSS_CHECK_VECTORS = {
  {
    base = "502d7ab70ebf0d087251c67d5c934eb0ef4a70d5c51a00ee54f73e1e08903425",
    exp = "f35d4f200a780822124a0b081179e3d4a0d35510ab6e959e2c",
    mod = "8e99ae1be2d241aeeb84195f9b108f9cf349d985159faa81e4481dfa13d53823",
    result = "72dcd8f95d33f62a754cf474d81b6d956f6679ebc5728a1ef6933847d8770e26",
  },
  {
    base = "25ae403fe777a8a29bdd6a5789cc8bbaab9d2464af1aacb53ae32135898e6bfa",
    exp = "80b8f4c2e5ddf71127f4eb3aa7a10564fce9969b05172e80ba",
    mod = "9304db81ec231dd86cdebb4eda07e4970efba2ff86aa0709e9a1dcde6d0d33c5",
    result = "13449129cb254007fe2810d95a9b437feebc78a31c1e2fd5073ec2ef6b4df5e6",
  },
  {
    base = "69bb23c104796692e0b335cace9437938c7f88608b5b34eac5ee3bb98f7ffe43",
    exp = "29dd6ffbfa8abc5492e855efc01b31186cb4b55dc01dcb6cf0",
    mod = "b751b52d96495d031ff4ab3d7784abe057a84ec928c26106bb0412086eed0137",
    result = "a654ff028a94c301f72b0aefacd2c5c65499787ee00c5f15a0d022587ad07b99",
  },
}

--- Run comprehensive self-test with known-answer test vectors
---
--- Covers conversions, schoolbook arithmetic across limb boundaries, modular
--- arithmetic, and modular exponentiation up to full 3072-bit SRP operands.
--- It also asserts the two invariants this module is built around: that the
--- optimised Montgomery path agrees with the slow reference path, and that the
--- OpenSSL-accelerated path is bit-identical to the pure-Lua one.
---
--- @return boolean result True if all tests pass, false otherwise
function bignum.selftest()
  print("Running bignum test vectors...")

  local from_hex = bignum.from_hex
  local to_hex = bignum.to_hex
  local from_number = bignum.from_number
  local equals = bignum.equals

  local N = from_hex(RFC5054_N_HEX)
  local G = from_number(5)
  local X = from_hex(VEC_X_HEX)
  local Y = from_hex(VEC_Y_HEX)
  local M = from_hex(VEC_M_HEX)

  -- Snapshot the OpenSSL state so the accelerator tests cannot leak.
  local saved_loaded = package.loaded["openssl"]
  local saved_preload = package.preload["openssl"]
  local saved_use = openssl_wrapper.enabled()

  -- The host's real binding, if any. Resolved now: install(nil) below makes require("openssl") fail.
  local real_loaded, real_binding = pcall(require, "openssl")
  if not real_loaded or type(real_binding) ~= "table" or type(real_binding.bn) ~= "table" then
    real_binding = nil
  end

  -- Limbs above which the stand-in's faults apply. Known-answer checks use at
  -- most 19 limbs, so a faulty stand-in still passes them.
  local WIDE = 32

  --- Stand-in lua-openssl binding over this module's own raw functions, so it
  --- tests routing and conversion, not OpenSSL. Like the real binding, it answers
  --- 0 for a zero divisor or modulus instead of raising.
  --- @param options table `spelling`: "powmod" or "mod_exp". `broken`: set of bn
  ---   function names that answer wrongly. `bad_remainder`: only divmod's
  ---   remainder is wrong. `small_only`: the exponentiation is wrong for any
  ---   multi-limb operand, which `Feature.BN`'s probe cannot see. Above `WIDE`
  ---   limbs, `mark_wide` adds one to each answer, `raise_wide` raises, and
  ---   `signed_hex` makes `tohex` prefix "-"
  --- @return table binding
  --- @return function calls `calls(name)` counts calls to one bn function; with no
  ---   name, the exponentiation under either spelling
  local function make_binding(options)
    local counts = {}
    local function enter(name, ...)
      counts[name] = (counts[name] or 0) + 1
      if options.raise_wide then
        for _, operand in ipairs({ ... }) do
          if #operand.value > WIDE then
            error("stand-in raised on a wide operand")
          end
        end
      end
      return options.broken ~= nil and options.broken[name] == true
    end
    local function handle(value)
      if options.mark_wide and #value > WIDE then
        return { value = add_raw(value, { 1 }) }
      end
      return { value = value }
    end
    local wrong = handle(from_number(1))
    local bnlib = {}
    bnlib.text = function(raw)
      enter("text")
      -- Matches lua-openssl's bn.text: big-endian bytes in.
      return { value = bignum.from_bytes(raw) }
    end
    bnlib.tohex = function(h)
      local hex = string_upper(to_hex(h.value))
      if options.signed_hex and #h.value > WIDE then
        return "-" .. hex
      end
      return hex
    end
    bnlib[options.spelling or "powmod"] = function(base, exp, modulus)
      if enter("powmod", base, exp, modulus) then
        return wrong
      end
      if options.small_only and (#base.value > 1 or #exp.value > 1 or #modulus.value > 1) then
        return wrong
      end
      if #modulus.value == 0 then
        return handle({})
      end
      return handle(mod_exp_reference(base.value, exp.value, modulus.value))
    end
    bnlib.mul = function(a, b)
      if enter("mul", a, b) then
        return wrong
      end
      return handle(mul_raw(a.value, b.value))
    end
    bnlib.divmod = function(a, b)
      if enter("divmod", a, b) then
        return wrong, wrong
      end
      if #b.value == 0 then
        return handle({}), handle({})
      end
      local quotient, remainder = divmod_raw(a.value, b.value)
      if options.bad_remainder then
        return handle(quotient), wrong
      end
      return handle(quotient), handle(remainder)
    end
    bnlib.mod = function(a, m)
      if enter("mod", a, m) then
        return wrong
      end
      if #m.value == 0 then
        return handle({})
      end
      local _, remainder = divmod_raw(a.value, m.value)
      return handle(remainder)
    end
    bnlib.mulmod = function(a, b, m)
      if enter("mulmod", a, b, m) then
        return wrong
      end
      if #m.value == 0 then
        return handle({})
      end
      local _, remainder = divmod_raw(mul_raw(a.value, b.value), m.value)
      return handle(remainder)
    end
    local binding = {
      version = function()
        return "0.9.2"
      end,
      bn = bnlib,
    }
    return binding, function(name)
      return counts[name or "powmod"] or 0
    end
  end

  --- Wrap a binding to record each hex string `bn.tohex` returns, as proof a result came from it.
  --- @param binding table Real lua-openssl module
  --- @return table proxy
  --- @return table<string, boolean> emitted Lowercase hex, leading zeros stripped
  local function recording_proxy(binding)
    local emitted = {}
    local bnlib = setmetatable({
      tohex = function(handle)
        local hex = binding.bn.tohex(handle)
        if type(hex) == "string" then
          emitted[(hex:lower():gsub("^0+(.)", "%1"))] = true
        end
        return hex
      end,
    }, { __index = binding.bn })
    return setmetatable({ bn = bnlib }, { __index = binding }), emitted
  end

  --- @param x BigNum[]
  --- @param y BigNum[]
  --- @return boolean
  local function same_values(x, y)
    if #x ~= #y then
      return false
    end
    for i = 1, #x do
      if type(y[i]) ~= "table" or not equals(x[i], y[i]) then
        return false
      end
    end
    return true
  end

  --- Every routed operation at SRP size, zeros included; mod_add and mod_sub get
  --- unreduced operands so they reach `mod`. Entries are { op, value, direct }, where
  --- `direct` is false for a value derived from `op`'s answer rather than returned by it.
  --- @return table[] entries
  local function routed_workload()
    local B = from_hex(SRP_EXP_B_HEX)
    local RA, RB = from_hex(SRP_RESULT_A_HEX), from_hex(SRP_RESULT_B_HEX)
    local NB = mul_raw(N, B)
    local wide = add_raw(NB, from_number(12345))
    local q1, r1 = bignum.divmod(wide, N)
    local q2, r2 = bignum.divmod(NB, N)
    return {
      { "mul", bignum.mul(N, B), true },
      { "divmod", q1, true },
      { "divmod", r1, true },
      { "divmod", q2, true },
      { "divmod", r2, true },
      { "mod", bignum.mod(wide, add_raw(N, { 1 })), true },
      { "mod", bignum.mod(NB, B), true },
      { "mod", bignum.mod_add(wide, NB, N), true },
      { "mod", bignum.mod_sub(N, wide, N), false },
      { "mod_mul", bignum.mod_mul(RA, RB, N), true },
      { "mod_exp", bignum.mod_exp(RA, from_number(65537), N), true },
      { "mod_exp", bignum.mod_exp(bignum.zero(), from_number(65537), N), true },
    }
  end

  --- @param entries table[]
  --- @return BigNum[]
  local function values_of(entries)
    local out = {}
    for i, entry in ipairs(entries) do
      out[i] = entry[2]
    end
    return out
  end

  --- Install a stand-in binding (or force acceleration off) and re-probe.
  --- @param binding table|nil Stand-in module, or nil for the pure-Lua path
  local function install(binding)
    package.loaded["openssl"] = binding
    if binding == nil then
      -- Force require("openssl") to fail regardless of what this host has.
      -- Each selftest stubs the same loader independently, which the language
      -- server reads as redefining one field; that is the intent here.
      --- @diagnostic disable-next-line: duplicate-set-field
      package.preload["openssl"] = function()
        error("simulated absent binding")
      end
    else
      package.preload["openssl"] = nil
    end
    openssl_wrapper.use(binding ~= nil)
  end

  -- Make the whole run deterministic: the vectors below exercise pure Lua.
  install(nil)

  local tests = {
    -- ---------------------------------------------------------------- bytes
    {
      name = "from_bytes/to_bytes round-trip",
      test = function()
        local raw = bytes.from_hex(VEC_X_HEX)
        return bignum.to_bytes(from_hex(VEC_X_HEX)) == raw and to_hex(bignum.from_bytes(raw)) == VEC_X_HEX
      end,
    },
    {
      name = "from_bytes ignores leading zero bytes",
      test = function()
        return equals(bignum.from_bytes(bytes.from_hex("00000001ff")), from_number(511))
      end,
    },
    {
      name = "to_bytes pads on the left when length is given",
      test = function()
        return bignum.to_bytes(from_number(511), 4) == bytes.from_hex("000001ff")
      end,
    },
    {
      name = "to_bytes preserves leading zeros through a round-trip",
      test = function()
        local padded = bignum.to_bytes(from_hex("0001ff"), 8)
        return #padded == 8 and padded == bytes.from_hex("00000000000001ff")
      end,
    },
    {
      name = "to_bytes rejects a length that cannot hold the value",
      test = function()
        return pcall(bignum.to_bytes, X, 8) == false
      end,
    },
    {
      name = "to_bytes of a 3072-bit value is exactly 384 bytes",
      test = function()
        return #bignum.to_bytes(N) == 384 and #bignum.to_bytes(N, 384) == 384
      end,
    },
    {
      name = "zero round-trips through bytes",
      test = function()
        local zero = bignum.zero()
        return bignum.is_zero(zero)
          and bignum.to_bytes(zero) == ""
          and bignum.to_bytes(zero, 4) == bytes.from_hex("00000000")
          and bignum.is_zero(bignum.from_bytes(""))
          and bignum.is_zero(bignum.from_bytes(bytes.from_hex("0000")))
      end,
    },
    -- ------------------------------------------------------------------ hex
    {
      name = "from_hex/to_hex round-trip on a 3072-bit value",
      test = function()
        return to_hex(N) == RFC5054_N_HEX and bignum.bit_length(N) == 3072
      end,
    },
    {
      name = "from_hex accepts uppercase and odd-length input",
      test = function()
        return equals(from_hex("ABCDEF"), from_hex("abcdef")) and to_hex(from_hex("fff")) == "fff"
      end,
    },
    {
      name = 'to_hex of zero is "0" and round-trips',
      test = function()
        return to_hex(bignum.zero()) == "0" and bignum.is_zero(from_hex("0")) and bignum.is_zero(from_hex(""))
      end,
    },
    {
      name = "from_hex rejects non-hex input",
      test = function()
        return pcall(from_hex, "12zz34") == false
      end,
    },
    -- --------------------------------------------------------------- number
    {
      name = "from_number across limb boundaries",
      test = function()
        return to_hex(from_number(0)) == "0"
          and to_hex(from_number(1)) == "1"
          and to_hex(from_number(16777215)) == "ffffff"
          and to_hex(from_number(16777216)) == "1000000"
          and to_hex(from_number(4294967296)) == "100000000"
      end,
    },
    {
      name = "from_number rejects negative, fractional and oversized input",
      test = function()
        return pcall(from_number, -1) == false
          and pcall(from_number, 1.5) == false
          and pcall(from_number, 2 ^ 60) == false
      end,
    },
    -- ----------------------------------------------------------- inspection
    {
      name = "bit_length and byte_length",
      test = function()
        return bignum.bit_length(bignum.zero()) == 0
          and bignum.byte_length(bignum.zero()) == 0
          and bignum.bit_length(X) == 256
          and bignum.byte_length(X) == 32
          and bignum.bit_length(Y) == 188
          and bignum.byte_length(Y) == 24
          and bignum.byte_length(N) == 384
      end,
    },
    {
      name = "compare and equals",
      test = function()
        return bignum.compare(X, Y) == 1
          and bignum.compare(Y, X) == -1
          and bignum.compare(X, X) == 0
          and equals(X, bignum.copy(X))
          and bignum.compare(from_number(16777216), from_number(16777215)) == 1
      end,
    },
    {
      name = "copy is independent of the original",
      test = function()
        local original = from_hex("0102030405060708090a")
        local duplicate = bignum.copy(original)
        duplicate[1] = 0
        return not equals(original, duplicate) and to_hex(original) == "102030405060708090a"
      end,
    },
    -- ----------------------------------------------------------- arithmetic
    {
      name = "add - unequal lengths (known answer)",
      test = function()
        return to_hex(bignum.add(X, Y)) == VEC_ADD_HEX and to_hex(bignum.add(Y, X)) == VEC_ADD_HEX
      end,
    },
    {
      name = "add - carry propagates across every limb",
      test = function()
        local all_ones = from_hex("ffffffffffffffffffffffffffffffffffffffffffffffff")
        return to_hex(bignum.add(all_ones, from_number(1))) == "1000000000000000000000000000000000000000000000000"
      end,
    },
    {
      name = "add - 3072-bit carry (N + 7)",
      test = function()
        return to_hex(bignum.add(N, from_number(7))) == SRP_BASE_OVER_N_HEX
      end,
    },
    {
      name = "add - identity with zero",
      test = function()
        return equals(bignum.add(X, bignum.zero()), X) and equals(bignum.add(bignum.zero(), X), X)
      end,
    },
    {
      name = "sub - unequal lengths (known answer)",
      test = function()
        return to_hex(bignum.sub(X, Y)) == VEC_SUB_HEX
      end,
    },
    {
      name = "sub - borrow propagates across every limb",
      test = function()
        local power = from_hex("1000000000000000000000000")
        local below = from_hex("ffffffffffffffffffffffff")
        return to_hex(bignum.sub(power, below)) == "1" and bignum.is_zero(bignum.sub(X, X))
      end,
    },
    {
      name = "sub - rejects a negative result",
      test = function()
        -- Equal widths too: only the final borrow can catch those.
        return pcall(bignum.sub, Y, X) == false
          and pcall(bignum.sub, from_number(5), from_number(7)) == false
          and pcall(bignum.sub, Y, bignum.add(Y, bignum.one())) == false
      end,
    },
    {
      name = "sub - rejects a wider subtrahend whose low limbs do not borrow",
      test = function()
        return pcall(bignum.sub, from_number(5), from_hex("1000000")) == false
          and pcall(bignum.sub, from_hex("ffffff"), from_hex("1000000")) == false
          and pcall(bignum.sub, X, bignum.add(X, from_hex("1" .. string_rep("0", 66)))) == false
          and to_hex(bignum.sub(from_hex("1000000"), from_hex("ffffff"))) == "1"
      end,
    },
    {
      name = "mul - unequal lengths (known answer)",
      test = function()
        return to_hex(bignum.mul(X, Y)) == VEC_MUL_HEX and to_hex(bignum.mul(Y, X)) == VEC_MUL_HEX
      end,
    },
    {
      name = "mul - all-ones squared exercises every carry",
      test = function()
        local all_ones = from_hex("ffffffffffffffffffffffffffffffffffffffffffffffff")
        local expected = "fffffffffffffffffffffffffffffffffffffffffffffffe"
          .. "000000000000000000000000000000000000000000000001"
        return to_hex(bignum.mul(all_ones, all_ones)) == expected
      end,
    },
    {
      name = "mul - power of two times its predecessor",
      test = function()
        local power = from_hex("1000000000000000000000000")
        local below = from_hex("ffffffffffffffffffffffff")
        return to_hex(bignum.mul(power, below)) == "ffffffffffffffffffffffff000000000000000000000000"
      end,
    },
    {
      name = "mul - zero and one",
      test = function()
        return bignum.is_zero(bignum.mul(X, bignum.zero()))
          and bignum.is_zero(bignum.mul(bignum.zero(), X))
          and equals(bignum.mul(X, bignum.one()), X)
      end,
    },
    {
      name = "divmod - multi-limb (known answer)",
      test = function()
        local quotient, remainder = bignum.divmod(X, Y)
        return to_hex(quotient) == VEC_QUO_HEX and to_hex(remainder) == VEC_REM_HEX
      end,
    },
    {
      name = "divmod - reconstructs the dividend",
      test = function()
        local quotient, remainder = bignum.divmod(X, Y)
        return equals(bignum.add(bignum.mul(quotient, Y), remainder), X) and bignum.compare(remainder, Y) < 0
      end,
    },
    {
      name = "divmod - single-limb divisor",
      test = function()
        local quotient, remainder = bignum.divmod(from_hex("1000000000000000000000001"), from_number(255))
        return equals(
          bignum.add(bignum.mul(quotient, from_number(255)), remainder),
          from_hex("1000000000000000000000001")
        ) and bignum.compare(remainder, from_number(255)) < 0
      end,
    },
    {
      name = "divmod - divisor larger than dividend",
      test = function()
        local quotient, remainder = bignum.divmod(Y, X)
        return bignum.is_zero(quotient) and equals(remainder, Y)
      end,
    },
    {
      name = "divmod - exact division leaves no remainder",
      test = function()
        local product = bignum.mul(X, Y)
        local quotient, remainder = bignum.divmod(product, Y)
        return equals(quotient, X) and bignum.is_zero(remainder)
      end,
    },
    {
      name = "divmod - rejects a zero divisor",
      test = function()
        return pcall(bignum.divmod, X, bignum.zero()) == false
      end,
    },
    {
      name = "mod - known answer",
      test = function()
        return to_hex(bignum.mod(X, M)) == VEC_MOD_X_HEX
      end,
    },
    -- ------------------------------------------------------ modular helpers
    {
      name = "mod_add - known answer",
      test = function()
        return to_hex(bignum.mod_add(X, Y, M)) == VEC_MOD_ADD_HEX
      end,
    },
    {
      name = "mod_sub - wraps to a non-negative residue when b > a",
      test = function()
        return to_hex(bignum.mod_sub(Y, X, M)) == VEC_MOD_SUB_HEX
      end,
    },
    {
      name = "mod_sub - plain difference when a >= b",
      test = function()
        return equals(bignum.mod_sub(X, Y, M), bignum.mod(bignum.sub(X, Y), M))
          and bignum.is_zero(bignum.mod_sub(X, X, M))
      end,
    },
    {
      name = "mod_mul - known answer",
      test = function()
        return to_hex(bignum.mod_mul(X, Y, M)) == VEC_MOD_MUL_HEX
      end,
    },
    -- ------------------------------------------------------------- mod_exp
    {
      name = "mod_exp - 4^13 mod 497 = 445",
      test = function()
        return equals(bignum.mod_exp(from_number(4), from_number(13), from_number(497)), from_number(445))
      end,
    },
    {
      name = "mod_exp - 2^10 mod 1000 = 24 (even modulus, reference path)",
      test = function()
        return equals(bignum.mod_exp(from_number(2), from_number(10), from_number(1000)), from_number(24))
          and equals(bignum.mod_exp(from_number(3), from_number(7), from_number(1000)), from_number(187))
      end,
    },
    {
      name = "mod_exp - exponent zero yields one",
      test = function()
        return equals(bignum.mod_exp(X, bignum.zero(), M), bignum.one())
          and equals(bignum.mod_exp(bignum.zero(), bignum.zero(), M), bignum.one())
      end,
    },
    {
      name = "mod_exp - base zero yields zero",
      test = function()
        return bignum.is_zero(bignum.mod_exp(bignum.zero(), from_number(5), from_number(7)))
          and bignum.is_zero(bignum.mod_exp(bignum.zero(), Y, M))
      end,
    },
    {
      name = "mod_exp - modulus one yields zero",
      test = function()
        return bignum.is_zero(bignum.mod_exp(X, Y, bignum.one()))
          and bignum.is_zero(bignum.mod_exp(from_number(123456789), bignum.zero(), bignum.one()))
      end,
    },
    {
      name = "mod_exp - rejects a zero modulus",
      test = function()
        return pcall(bignum.mod_exp, X, Y, bignum.zero()) == false
      end,
    },
    {
      name = "mod_exp - 192-bit modulus (known answer)",
      test = function()
        return to_hex(bignum.mod_exp(X, Y, M)) == VEC_MOD_EXP_HEX
      end,
    },
    {
      name = "mod_exp - RFC 5054 group 15: 5^a mod N, 256-bit exponent",
      test = function()
        return to_hex(bignum.mod_exp(G, from_hex(SRP_EXP_A_HEX), N)) == SRP_RESULT_A_HEX
      end,
    },
    {
      name = "mod_exp - RFC 5054 group 15: 5^b mod N, full 3072-bit exponent",
      test = function()
        return to_hex(bignum.mod_exp(G, from_hex(SRP_EXP_B_HEX), N)) == SRP_RESULT_B_HEX
      end,
    },
    {
      name = "mod_exp - RFC 5054 group 15: base greater than the modulus",
      test = function()
        local base = bignum.add(N, from_number(7))
        return to_hex(bignum.mod_exp(base, from_hex(SRP_EXP_A_HEX), N)) == SRP_RESULT_OVER_HEX
      end,
    },
    {
      name = "mod_exp - Montgomery path matches the slow reference path",
      test = function()
        for _, vector in ipairs(CROSS_CHECK_VECTORS) do
          local base, exp = from_hex(vector.base), from_hex(vector.exp)
          local modulus = from_hex(vector.mod)
          local fast = mod_exp_montgomery(base, exp, modulus)
          local slow = mod_exp_reference(base, exp, modulus)
          if to_hex(fast) ~= vector.result or to_hex(slow) ~= vector.result then
            return false
          end
        end
        return true
      end,
    },
    -- ------------------------------------------------------ acceleration
    {
      name = "accelerated mod_exp is identical to pure Lua (bn.powmod spelling)",
      test = function()
        install(nil)
        local pure = bignum.mod_exp(X, Y, M)
        local binding, calls = make_binding({ spelling = "powmod" })
        install(binding)
        local accelerated = bignum.mod_exp(X, Y, M)
        install(nil)
        -- calls() > 1 proves the routing fired: once to verify, once for real.
        return calls() > 1 and equals(accelerated, pure) and to_hex(accelerated) == VEC_MOD_EXP_HEX
      end,
    },
    {
      name = "accelerated mod_exp is identical to pure Lua (bn.mod_exp spelling)",
      test = function()
        install(nil)
        local pure = bignum.mod_exp(G, from_hex(SRP_EXP_A_HEX), N)
        local binding, calls = make_binding({ spelling = "mod_exp" })
        install(binding)
        local accelerated = bignum.mod_exp(G, from_hex(SRP_EXP_A_HEX), N)
        install(nil)
        return calls() > 1 and equals(accelerated, pure) and to_hex(accelerated) == SRP_RESULT_A_HEX
      end,
    },
    {
      name = "accelerated results are canonical limb tables, not handles",
      test = function()
        local binding = make_binding({})
        install(binding)
        local accelerated = bignum.mod_exp(X, Y, M)
        install(nil)
        -- Same canonical type either way, so a use_openssl() toggle mid-flight
        -- can never produce mixed-type operands.
        return type(accelerated) == "table" and equals(bignum.mod_mul(accelerated, bignum.one(), M), accelerated)
      end,
    },
    {
      name = "a binding that returns wrong answers is rejected, not trusted",
      test = function()
        local binding = make_binding({ broken = { powmod = true } })
        install(binding)
        local result = bignum.mod_exp(X, Y, M)
        install(nil)
        return to_hex(result) == VEC_MOD_EXP_HEX
      end,
    },
    {
      -- With raise_wide, every answer has to come back through the pure-Lua fallback.
      name = "every routed operation matches pure Lua at 3072 bits, zeros included, even when the binding raises",
      test = function()
        install(nil)
        local pure = values_of(routed_workload())
        for _, options in ipairs({ {}, { raise_wide = true } }) do
          local binding, calls = make_binding(options)
          install(binding)
          local accelerated = values_of(routed_workload())
          install(nil)
          if not same_values(pure, accelerated) then
            return false
          end
          -- At least two calls each: the known-answer check, then real work.
          for _, name in ipairs({ "mul", "divmod", "mod", "mulmod", "powmod" }) do
            if calls(name) < 2 then
              return false
            end
          end
        end
        return true
      end,
    },
    {
      name = "results come from the binding, not a silent fallback",
      test = function()
        install(nil)
        local pure = routed_workload()
        local binding = make_binding({ mark_wide = true })
        install(binding)
        local accelerated = routed_workload()
        install(nil)
        local marked = {}
        for i, entry in ipairs(pure) do
          local op, value, direct = entry[1], entry[2], entry[3]
          local expected = value
          if direct and #value > WIDE then
            expected = add_raw(value, { 1 })
            marked[op] = true
          end
          if not equals(accelerated[i][2], expected) then
            return false
          end
        end
        return marked.mul and marked.divmod and marked.mod and marked.mod_mul and marked.mod_exp or false
      end,
    },
    {
      -- Routed: the bn function runs twice (check, then work). Not routed: nothing is converted.
      name = "calls route where the work per converted limb reaches the threshold, and only there",
      test = function()
        local B = from_hex(SRP_EXP_B_HEX)
        local wide = mul_raw(N, B)
        local seven, byte = from_number(7), from_number(255)
        local a47, a48, b48 =
          from_hex(string_rep("ab", 141)), from_hex(string_rep("ab", 144)), from_hex(string_rep("cd", 144))
        --- @type table[]
        local shapes = {
          { false, bignum.mul, X, Y }, -- narrow operands
          { false, bignum.divmod, X, Y },
          { false, bignum.mod, X, M },
          { false, bignum.mul, a47, b48 }, -- 2256 limb products for 190 limbs converted: under 12
          { "mul", bignum.mul, a48, b48 }, -- 2304 for 192: exactly 12
          { false, bignum.mul, seven, wide }, -- a one-limb factor, either side
          { false, bignum.mul, wide, seven },
          { false, bignum.mul, bignum.zero(), bignum.zero() },
          { false, bignum.divmod, wide, byte }, -- a one-limb divisor
          { false, bignum.mod, wide, byte },
          { false, bignum.divmod, add_raw(N, B), N }, -- a quotient of a limb or two
          { false, bignum.mod, add_raw(N, B), N },
          { false, bignum.mod, N, B },
          { false, bignum.add, N, B }, -- linear at any width
          { false, bignum.sub, add_raw(N, B), B },
          { false, bignum.mod_add, N, B, N }, -- operands already reduced
          { false, bignum.mod_sub, B, N, N },
          { false, bignum.mod_mul, B, seven, N },
          { false, bignum.mod_mul, bignum.zero(), wide, N }, -- a zero factor
          { "mulmod", bignum.mod_mul, wide, from_number(3), N }, -- the reduction dominates
          { "mod", bignum.mod_add, wide, from_number(12345), N }, -- an unreduced operand
          { "mod", bignum.mod_sub, seven, wide, N },
        }
        for i, shape in ipairs(shapes) do
          local routed_to, call = shape[1], shape[2]
          install(nil)
          local pure = { call(shape[3], shape[4], shape[5]) }
          local binding, calls = make_binding({})
          install(binding)
          local got = { call(shape[3], shape[4], shape[5]) }
          install(nil)
          local routed = routed_to and calls(routed_to) == 2 or (not routed_to and calls("text") == 0)
          if not (routed and same_values(pure, got)) then
            error("shape " .. i .. " routed wrongly or changed its answer")
          end
        end
        return #a47 == 47 and #a48 == 48
      end,
    },
    {
      name = "a binding with one broken operation loses only that operation",
      test = function()
        local B = from_hex(SRP_EXP_B_HEX)
        local RA, RB = from_hex(SRP_RESULT_A_HEX), from_hex(SRP_RESULT_B_HEX)
        local wide = add_raw(mul_raw(N, B), from_number(12345))
        local N1 = add_raw(N, { 1 })
        local cases = {
          { broken = { mul = true }, bn = "mul", op = "mul" },
          { broken = { divmod = true }, bn = "divmod", op = "divmod" },
          { bad_remainder = true, bn = "divmod", op = "divmod" },
          { broken = { mod = true }, bn = "mod", op = "mod" },
          { broken = { mulmod = true }, bn = "mulmod", op = "mod_mul" },
        }
        local function run(op)
          if op == "mul" then
            return { bignum.mul(N, B) }
          elseif op == "divmod" then
            local quotient, remainder = bignum.divmod(wide, N)
            return { quotient, remainder }
          elseif op == "mod" then
            return { bignum.mod(wide, N1) }
          end
          return { bignum.mod_mul(RA, RB, N) }
        end
        for _, case in ipairs(cases) do
          install(nil)
          local pure = run(case.op)
          local binding, calls = make_binding(case)
          install(binding)
          local first, second = run(case.op), run(case.op)
          local verdicts = {}
          for _, op in ipairs({ "mul", "divmod", "mod", "mod_mul", "mod_exp" }) do
            verdicts[op] = bignum.is_accelerated(op)
          end
          install(nil)
          -- One call: the failed check is cached, not repeated per call.
          if not (same_values(pure, first) and same_values(pure, second) and calls(case.bn) == 1) then
            return false
          end
          for op, accelerated in pairs(verdicts) do
            if accelerated ~= (op ~= case.op) then
              return false
            end
          end
        end
        return true
      end,
    },
    {
      name = "a zero divisor or modulus raises the pure-Lua error with acceleration on",
      test = function()
        local wide = mul_raw(N, N)
        local zero = bignum.zero()
        local function failures()
          local messages = {}
          for i, call in ipairs({
            { bignum.divmod, wide, zero },
            { bignum.mod, wide, zero },
            { bignum.mod_mul, N, N, zero },
            { bignum.mod_add, N, N, zero },
            { bignum.mod_sub, N, wide, zero },
            { bignum.mod_exp, N, N, zero },
          }) do
            local ok, message = pcall(call[1], call[2], call[3], call[4])
            messages[i] = (not ok) and tostring(message) or false
          end
          return messages
        end
        install(nil)
        local expected = failures()
        local binding, calls = make_binding({})
        install(binding)
        local got = failures()
        install(nil)
        for i = 1, #expected do
          if expected[i] == false or got[i] ~= expected[i] then
            return false
          end
        end
        -- mod_mul(N, N, 0) passes the size rule, so require_nonzero is what kept it from mulmod.
        return calls("mulmod") == 1
      end,
    },
    {
      name = "signed hex from the binding is refused, not read as negative limbs",
      test = function()
        -- X * 16^112 is 30 limbs, wide enough against N to route. N times it is
        -- 944 hex digits, not a multiple of a limb's 6, so the "-" shares a chunk
        -- with digits and from_hex alone would read it as a negative limb.
        local wide_x = from_hex(VEC_X_HEX .. string_rep("0", 112))
        install(nil)
        local pure = bignum.mul(N, wide_x)
        local binding, calls = make_binding({ signed_hex = true })
        install(binding)
        local product = bignum.mul(N, wide_x)
        install(nil)
        return calls("mul") == 2 and equals(product, pure)
      end,
    },
    {
      name = (real_binding and "the host's lua-openssl agrees with pure Lua and is used wherever it is trusted")
        or "the host's lua-openssl agrees with pure Lua (skipped: no binding on this host)",
      test = function()
        if real_binding == nil then
          return true
        end
        install(nil)
        local pure = routed_workload()
        local proxy, emitted = recording_proxy(real_binding)
        install(proxy)
        -- Declining an operation is allowed here; each one trusted must return the binding's answer.
        local trusted = {}
        for _, op in ipairs({ "mul", "divmod", "mod", "mod_mul", "mod_exp" }) do
          trusted[op] = bignum.is_accelerated(op)
        end
        local accelerated = routed_workload()
        local exponentiated = trusted.mod_exp and bignum.mod_exp(G, from_hex(SRP_EXP_A_HEX), N) or nil
        install(nil)
        if not same_values(values_of(pure), values_of(accelerated)) then
          return false
        end
        for _, entry in ipairs(accelerated) do
          local op, value, direct = entry[1], entry[2], entry[3]
          if direct and trusted[op] and not bignum.is_zero(value) and not emitted[to_hex(value)] then
            return false
          end
        end
        return exponentiated == nil or (to_hex(exponentiated) == SRP_RESULT_A_HEX and emitted[SRP_RESULT_A_HEX] == true)
      end,
    },
    {
      name = "an absent binding falls back to pure Lua",
      test = function()
        install(nil)
        openssl_wrapper.use(true)
        local result = bignum.mod_exp(from_number(4), from_number(13), from_number(497))
        install(nil)
        return equals(result, from_number(445))
      end,
    },
    -- ----------------------------------------------- is_accelerated reporting
    -- A caller told only "false" cannot tell a host that will never accelerate
    -- from one where nobody called use_openssl(true), and the two need opposite
    -- responses. Each case below pins the phrase that distinguishes them.
    {
      -- The Control4 case: a working binding is present and nobody enabled it.
      name = "is_accelerated blames the flag when acceleration was never enabled, and the binding is untouched",
      test = function()
        local binding, calls = make_binding({})
        install(binding)
        openssl_wrapper.use(false)
        routed_workload()
        local accelerated, reason = bignum.is_accelerated()
        install(nil)
        return accelerated == false
          and type(reason) == "string"
          and reason:find("crypto.use_openssl(true)", 1, true) ~= nil
          and calls("text") == 0
      end,
    },
    {
      name = "is_accelerated blames the host when the binding is absent",
      test = function()
        install(nil)
        openssl_wrapper.use(true)
        local accelerated, reason = bignum.is_accelerated()
        install(nil)
        return accelerated == false
          and type(reason) == "string"
          and reason:find("not available", 1, true) ~= nil
          and reason:find("use_openssl", 1, true) == nil
      end,
    },
    {
      -- The binding computes 4^13 mod 497 correctly, so Feature.BN's probe
      -- passes; it is wrong on the multi-limb vector, so mod_exp will not use
      -- it. is_accelerated must agree with mod_exp, not with the feature gate.
      name = "is_accelerated blames the known-answer check for a single-limb-only binding",
      test = function()
        local binding = make_binding({ small_only = true })
        install(binding)
        local gated = openssl_wrapper.get(openssl_wrapper.Feature.BN) ~= nil
        local accelerated, reason = bignum.is_accelerated()
        local result = bignum.mod_exp(X, Y, M)
        install(nil)
        return gated == true
          and accelerated == false
          and type(reason) == "string"
          and reason:find("known-answer check", 1, true) ~= nil
          and to_hex(result) == VEC_MOD_EXP_HEX
      end,
    },
    {
      name = "is_accelerated is true with no reason for a trusted binding",
      test = function()
        local binding = make_binding({})
        install(binding)
        local accelerated, reason = bignum.is_accelerated()
        install(nil)
        return accelerated == true and reason == nil
      end,
    },
  }

  local passed = 0
  for _, test in ipairs(tests) do
    local ok, result = pcall(test.test)
    if ok and result == true then
      print("  ✅ PASS: " .. test.name)
      passed = passed + 1
    else
      print("  ❌ FAIL: " .. test.name .. (ok and "" or (" - " .. tostring(result))))
    end
  end

  -- Restore the caller's state, acceleration choice included, so later tests in this process are unaffected.
  package.loaded["openssl"] = saved_loaded
  package.preload["openssl"] = saved_preload
  openssl_wrapper.use(saved_use)

  print(string_format("\nBignum result: %d/%d tests passed\n", passed, #tests))
  return passed == #tests
end

--- Run performance benchmarks
---
--- The headline number is a 3072-bit modular exponentiation with a full-size
--- 3072-bit exponent: that is the SRP-6a server operation, and it decides
--- whether the pure-Lua path is shippable on an embedded controller. Iteration
--- counts are small because a single such operation takes seconds.
function bignum.benchmark()
  local N = bignum.from_hex(RFC5054_N_HEX)
  local G = bignum.from_number(5)
  local exp_short = bignum.from_hex(SRP_EXP_A_HEX)
  local exp_full = bignum.from_hex(SRP_EXP_B_HEX)
  local wide = bignum.mul(N, N)

  print("Modular exponentiation (RFC 5054 group 15, 3072-bit N):")
  benchmark_op("mod_exp 3072-bit exponent", function()
    bignum.mod_exp(G, exp_full, N)
  end, 2)

  benchmark_op("mod_exp 256-bit exponent", function()
    bignum.mod_exp(G, exp_short, N)
  end, 5)

  print("\nCore arithmetic:")
  benchmark_op("mul 3072 x 3072 bits", function()
    bignum.mul(N, N)
  end, 200)

  benchmark_op("divmod 6144 / 3072 bits", function()
    bignum.divmod(wide, N)
  end, 100)

  benchmark_op("mod_mul 3072-bit", function()
    bignum.mod_mul(N, N, N)
  end, 100)
end

return bignum
