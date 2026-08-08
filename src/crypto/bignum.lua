--- @module "crypto.bignum"
--- Arbitrary-precision unsigned integer arithmetic, sized for 3072-bit modular
--- exponentiation (SRP-6a / RFC 5054 group 15).
---
--- The hot path is `mod_exp`, which uses Montgomery multiplication plus a
--- sliding-window exponentiation. See the notes above `mod_exp_montgomery` for
--- why those two were chosen over the naive "square and multiply with a full
--- divmod after every step".
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
local string_format = string.format
local string_rep = string.rep
local string_sub = string.sub
local string_upper = string.upper
local table_concat = table.concat

-- ============================================================================
-- CONSTANTS
-- ============================================================================

--- @alias BigNum integer[] Little-endian array of 24-bit limbs; {} is zero.

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

--- Known-answer vector used to verify an OpenSSL binding before trusting it.
--- Deliberately multi-limb so a binding that mis-parses long hex is caught.
local ACCEL_CHECK_BASE = "c0ffee0123456789abcdef0123456789abcdef0123456789ab"
local ACCEL_CHECK_EXP = "1234567890abcdef1234"
local ACCEL_CHECK_MOD = "fffffffffffffffffffffffffffffffffffffffeffffee37"
local ACCEL_CHECK_RESULT = "e2f14166c00a4c44a535f801534727158dcfce58a82049b7"

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
-- used only as an internal accelerator *inside* mod_exp: operands are converted
-- into openssl.bn handles (big-endian bytes in via bn.text), the modexp runs
-- there, and the result is converted straight back to a limb table (hex out via
-- bn.tohex). That is exactly the conversion path Feature.BN probes.
--
-- Rationale: crypto.use_openssl() can be toggled at runtime, so if handles were
-- sometimes userdata and sometimes tables, a toggle mid-flight would produce
-- mixed-type operands and silent breakage. Keeping one canonical type makes the
-- accelerator invisible to callers -- results are identical with and without
-- it, and selftest() asserts exactly that. The conversion cost is a few hundred
-- bytes moved in and out versus a 3072-bit modexp, so it is noise.

--- Binding whose behaviour has already been verified, and the verdict.
local _verified_binding = nil
local _verified_ok = false

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

--- Run one modular exponentiation through the OpenSSL binding.
--- @param openssl table Loaded lua-openssl module
--- @param base BigNum Base
--- @param exp BigNum Exponent
--- @param m BigNum Modulus
--- @return BigNum result Canonical limb table
local function mod_exp_openssl(openssl, base, exp, m)
  local bnlib = openssl.bn
  local result = bn_powmod(bnlib)(bn_from_bignum(bnlib, base), bn_from_bignum(bnlib, exp), bn_from_bignum(bnlib, m))
  local hex = bnlib.tohex(result)
  if type(hex) ~= "string" or hex == "" then
    error("bignum: openssl bn.tohex did not return hex")
  end
  return bignum.from_hex(hex)
end

--- Decide whether a binding may be trusted for real work.
---
--- `Feature.BN` proves the three entry points exist and round-trip on a
--- single-digit value; it cannot prove that this build's constructor parses a
--- long hex string the way this module writes it. So the first time a given
--- binding table is seen, run one multi-limb known-answer vector through it and
--- cache the verdict. A binding that fails silently falls back to pure Lua
--- rather than returning wrong answers.
---
--- @param openssl table Loaded lua-openssl module
--- @return boolean usable
local function accelerator_ready(openssl)
  if _verified_binding == openssl then
    return _verified_ok
  end
  _verified_binding = openssl
  _verified_ok = false
  local ok, result = pcall(
    mod_exp_openssl,
    openssl,
    bignum.from_hex(ACCEL_CHECK_BASE),
    bignum.from_hex(ACCEL_CHECK_EXP),
    bignum.from_hex(ACCEL_CHECK_MOD)
  )
  if ok and type(result) == "table" and compare_raw(result, bignum.from_hex(ACCEL_CHECK_RESULT)) == 0 then
    _verified_ok = true
  end
  return _verified_ok
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

--- Multiplication.
--- @param a BigNum First factor
--- @param b BigNum Second factor
--- @return BigNum product
function bignum.mul(a, b)
  return mul_raw(a, b)
end

--- Division with remainder.
--- @param a BigNum Dividend
--- @param b BigNum Divisor (must be non-zero)
--- @return BigNum quotient floor(a / b)
--- @return BigNum remainder a - quotient * b
function bignum.divmod(a, b)
  return divmod_raw(a, b)
end

--- Remainder of a divided by b.
--- @param a BigNum Dividend
--- @param b BigNum Modulus (must be non-zero)
--- @return BigNum remainder
function bignum.mod(a, b)
  local _, r = divmod_raw(a, b)
  return r
end

--- Modular addition.
--- @param a BigNum First addend
--- @param b BigNum Second addend
--- @param m BigNum Modulus (must be non-zero)
--- @return BigNum result (a + b) mod m
function bignum.mod_add(a, b, m)
  local _, r = divmod_raw(add_raw(a, b), m)
  return r
end

--- Modular subtraction, always returning a non-negative residue.
--- SRP computes B - k*g^x, where the subtraction can go negative, so this wraps
--- rather than erroring.
--- @param a BigNum Minuend
--- @param b BigNum Subtrahend
--- @param m BigNum Modulus (must be non-zero)
--- @return BigNum result (a - b) mod m
function bignum.mod_sub(a, b, m)
  local _, ra = divmod_raw(a, m)
  local _, rb = divmod_raw(b, m)
  if compare_raw(ra, rb) >= 0 then
    return sub_raw(ra, rb)
  end
  return sub_raw(add_raw(ra, m), rb)
end

--- Modular multiplication.
--- @param a BigNum First factor
--- @param b BigNum Second factor
--- @param m BigNum Modulus (must be non-zero)
--- @return BigNum result (a * b) mod m
function bignum.mod_mul(a, b, m)
  local _, r = divmod_raw(mul_raw(a, b), m)
  return r
end

--- Modular exponentiation -- the hot path for SRP-6a.
---
--- Dispatch order: a verified OpenSSL binding if acceleration is enabled,
--- otherwise Montgomery + sliding window for odd moduli, otherwise the slow
--- reference path. All three return identical values.
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

  local openssl = openssl_wrapper.get(openssl_wrapper.Feature.BN)
  if openssl ~= nil and accelerator_ready(openssl) then
    local ok, result = pcall(mod_exp_openssl, openssl, base, exp, m)
    if ok and type(result) == "table" then
      return result
    end
  end

  if m[1] % 2 == 1 then
    return mod_exp_montgomery(base, exp, m)
  end
  -- Montgomery needs an odd modulus; even moduli are not used by SRP.
  return mod_exp_reference(base, exp, m)
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
local VEC_X_HEX = "f0e1d2c3b4a5968778695a4b3c2d1e0fdeadbeefcafebabe0123456789abcdef"
local VEC_Y_HEX = "fedcba987654321fedcba9876543210abcdef0123456789"
local VEC_M_HEX = "fffffffffffffffffffffffffffffffeffffffffffffffff"
local VEC_ADD_HEX = "f0e1d2c3b4a59687885725f4c3926131dd8a79884152ecceacf13468acf13578"
local VEC_SUB_HEX = "f0e1d2c3b4a59687687b8ea1b4c7daeddfd1045754aa88ad5555566666666666"
local VEC_MUL_HEX = table.concat({
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

  --- Build a stand-in lua-openssl binding. Real lua-openssl is not installed
  --- here, so this validates the *routing* and the bytes-in/hex-out conversion,
  --- not real OpenSSL arithmetic: the stand-in's modular exponentiation
  --- delegates to this module's own slow reference path.
  --- @param options table `spelling` is "powmod" or "mod_exp"; `broken` returns wrong answers
  --- @return table binding
  --- @return function calls Returns how many times the exponentiation was invoked
  local function make_binding(options)
    local calls = 0
    local bnlib = {}
    bnlib.text = function(raw)
      -- Matches lua-openssl's bn.text: big-endian bytes in.
      return { value = bignum.from_bytes(raw) }
    end
    bnlib.tohex = function(handle)
      return string_upper(to_hex(handle.value))
    end
    bnlib[options.spelling or "powmod"] = function(base, exp, modulus)
      calls = calls + 1
      if options.broken then
        return { value = from_number(1) }
      end
      return { value = mod_exp_reference(base.value, exp.value, modulus.value) }
    end
    local binding = {
      version = function()
        return "0.9.2"
      end,
      bn = bnlib,
    }
    return binding, function()
      return calls
    end
  end

  --- Install a stand-in binding (or force acceleration off) and re-probe.
  --- @param binding table|nil Stand-in module, or nil for the pure-Lua path
  local function install(binding)
    package.loaded["openssl"] = binding
    if binding == nil then
      -- Force require("openssl") to fail regardless of what this host has.
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
        return pcall(bignum.sub, Y, X) == false
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
        local binding = make_binding({ broken = true })
        install(binding)
        local result = bignum.mod_exp(X, Y, M)
        install(nil)
        return to_hex(result) == VEC_MOD_EXP_HEX
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

  -- Restore the module-load default so later tests in this process are unaffected.
  package.loaded["openssl"] = saved_loaded
  package.preload["openssl"] = saved_preload
  openssl_wrapper.use(os.getenv("CRYPTO_USE_OPENSSL") == "1" or os.getenv("CRYPTO_USE_OPENSSL") == "true")

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
