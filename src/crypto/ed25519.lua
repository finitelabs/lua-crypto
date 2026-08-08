--- @module "crypto.ed25519"
--- Ed25519 (RFC 8032) EdDSA signatures in portable pure Lua.
---
--- PureEdDSA over edwards25519 with SHA-512, no context and no prehashing
--- (RFC 8032 section 5.1). The field arithmetic is the TweetNaCl 16x16-bit limb
--- representation shared with `crypto.x25519`; point arithmetic uses extended
--- twisted Edwards coordinates (X, Y, Z, T).
---
--- Portability: no Lua 5.3+ integer syntax is used, every intermediate value is
--- exactly representable as an IEEE double, so the module behaves identically on
--- Lua 5.1/5.2/5.3/5.4/5.5 and LuaJIT 2.0/2.1.
--- @class crypto.ed25519
local ed25519 = {}

local bit32 = require("bitn").bit32

local random = require("crypto.random")
local sha512_mod = require("crypto.sha512")
local utils = require("crypto.utils")
local bytes = utils.bytes
local benchmark_op = utils.benchmark.benchmark_op

-- Local references for performance
local bit32_raw_band = bit32.raw_band
local bit32_raw_bor = bit32.raw_bor
local bit32_raw_bxor = bit32.raw_bxor
local bit32_raw_rshift = bit32.raw_rshift
local floor = math.floor
local sha512 = sha512_mod.sha512
local string_byte = string.byte
local string_char = string.char
local string_rep = string.rep
local string_sub = string.sub
local table_concat = table.concat

-- ============================================================================
-- CURVE25519 FIELD ARITHMETIC (shared field with X25519: p = 2^255 - 19)
-- ============================================================================

--- @alias FieldElement integer[] 16-element array (indices 1-16) representing a field element
--- @alias ProductArray integer[] 31-element array (indices 1-31) for multiplication products
--- @alias ByteArray integer[] Array of byte values (indices start at 1)
--- @alias EdPoint FieldElement[] 4-element array {X, Y, Z, T} in extended twisted Edwards coordinates

--- Initialize a 16-element field element with zeros
--- @return FieldElement fe Initialized field element
local function create_field_element()
  local arr = {}
  for i = 1, 16 do
    arr[i] = 0
  end
  return arr
end

--- Initialize a 31-element product array with zeros
--- @return ProductArray arr Initialized array
local function create_product_array()
  local arr = {}
  for i = 1, 31 do
    arr[i] = 0
  end
  return arr
end

--- Initialize an n-element byte array with zeros
--- @param n integer Number of elements
--- @return ByteArray arr Initialized array
local function create_byte_array(n)
  local arr = {}
  for i = 1, n do
    arr[i] = 0
  end
  return arr
end

--- Initialize an extended twisted Edwards point (all four coordinates zeroed)
--- @return EdPoint p Initialized point
local function create_point()
  return { create_field_element(), create_field_element(), create_field_element(), create_field_element() }
end

-- Pre-allocated product array for fe_mul() to avoid repeated allocation
local mul_prod = create_product_array()

-- Pre-allocated arrays for fe_pack() to avoid repeated allocation
local pack_t = create_field_element()
local pack_m = create_field_element()

-- Pre-allocated arrays for fe_inv() / fe_pow2523()
local inv_c = create_field_element()
local pow_c = create_field_element()

-- Pre-allocated byte buffers used by par25519() / fe_eq()
local cmp_a = create_byte_array(32)
local cmp_b = create_byte_array(32)

--- Carry/reduce a field element so every limb ends up in [0, 2^16)
---
--- Overflow bound: `floor(v * 1/0x10000)` is exact for any |v| < 2^53 because
--- 1/0x10000 is a power of two, so the multiply is error-free. Callers keep
--- limbs well under that (see fe_mul).
--- @param out integer[] Array to perform carry on
local function fe_carry(out)
  for i = 1, 16 do
    local v = out[i] + 0x10000
    local c = floor(v * 0.0000152587890625) -- 1/0x10000 = 0.0000152587890625
    if i < 16 then
      out[i + 1] = out[i + 1] + c - 1
    else
      out[1] = out[1] + 38 * (c - 1)
    end
    out[i] = v - c * 0x10000
  end
end

--- Conditional swap of two limb arrays based on a bit value (branch-free)
--- @param a integer[] First array
--- @param b integer[] Second array
--- @param bit integer Bit value (0 or 1)
local function fe_cswap(a, b, bit)
  for i = 1, 16 do
    a[i], b[i] = a[i] * ((bit - 1) % 2) + b[i] * bit, b[i] * ((bit - 1) % 2) + a[i] * bit
  end
end

--- Unpack a 32-byte little-endian value into a limb array (clears the top bit)
--- @param out integer[] Output limb array
--- @param a integer[] Input byte array (32 bytes)
local function fe_unpack(out, a)
  for i = 1, 16 do
    out[i] = a[2 * i - 1] + a[2 * i] * 0x100
  end
  out[16] = bit32_raw_band(out[16], 0x7fff)
end

-- Pre-allocated prime constant for fe_pack()
local PRIME = {
  0xffed,
  0xffff,
  0xffff,
  0xffff,
  0xffff,
  0xffff,
  0xffff,
  0xffff,
  0xffff,
  0xffff,
  0xffff,
  0xffff,
  0xffff,
  0xffff,
  0xffff,
  0x7fff,
}

--- Pack a limb array into 32 little-endian bytes with full modular reduction
--- @param out integer[] Output byte array (32 bytes)
--- @param a integer[] Input limb array
local function fe_pack(out, a)
  -- Reuse pre-allocated arrays
  local t, m = pack_t, pack_m
  for i = 1, 16 do
    t[i] = a[i]
  end
  fe_carry(t)
  fe_carry(t)
  fe_carry(t)
  for _ = 1, 2 do
    m[1] = t[1] - PRIME[1]
    for i = 2, 16 do
      local prev = m[i - 1]
      m[i] = t[i] - PRIME[i] - (floor(prev * 0.0000152587890625) % 2)
      m[i - 1] = (prev + 0x10000) % 0x10000
    end
    local c = floor(m[16] * 0.0000152587890625) % 2
    fe_cswap(t, m, 1 - c)
  end
  for i = 1, 16 do
    local ti = t[i]
    out[2 * i - 1] = ti % 0x100
    out[2 * i] = floor(ti * 0.00390625) -- 1/256
  end
end

--- Add two field elements
--- @param out integer[] Output array
--- @param a integer[] First input array
--- @param b integer[] Second input array
local function fe_add(out, a, b)
  for i = 1, 16 do
    out[i] = a[i] + b[i]
  end
end

--- Subtract two field elements
--- @param out integer[] Output array
--- @param a integer[] First input array
--- @param b integer[] Second input array
local function fe_sub(out, a, b)
  for i = 1, 16 do
    out[i] = a[i] - b[i]
  end
end

--- Multiply two field elements modulo 2^255 - 19
---
--- Overflow bound: inputs are always either fe_mul/fe_carry outputs (limbs in
--- [0, 2^16)) or at most a sum of two such values (|limb| < 2^18). The
--- schoolbook accumulator therefore stays below 16 * 2^18 * 2^18 = 2^40, and the
--- 38x fold-down of the high half keeps it below 39 * 2^40 < 2^46 << 2^53, so
--- every intermediate is exact in IEEE doubles on 5.1/5.2/LuaJIT.
--- @param out integer[] Output array
--- @param a integer[] First input array
--- @param b integer[] Second input array
local function fe_mul(out, a, b)
  -- Reuse pre-allocated array and clear it
  local prod = mul_prod
  for i = 1, 31 do
    prod[i] = 0
  end
  -- Schoolbook multiplication
  for i = 1, 16 do
    local ai = a[i]
    for j = 1, 16 do
      prod[i + j - 1] = prod[i + j - 1] + ai * b[j]
    end
  end
  -- Reduce mod 2^255-19 (multiply high limbs by 38 and add to low)
  for i = 1, 15 do
    prod[i] = prod[i] + 38 * prod[i + 16]
  end
  for i = 1, 16 do
    out[i] = prod[i]
  end
  fe_carry(out)
  fe_carry(out)
end

--- Square a field element
--- @param out integer[] Output array
--- @param a integer[] Input array
local function fe_sq(out, a)
  fe_mul(out, a, a)
end

--- Copy a field element
--- @param out integer[] Output array
--- @param a integer[] Input array
local function fe_copy(out, a)
  for i = 1, 16 do
    out[i] = a[i]
  end
end

--- Compute the modular inverse a^(p-2) using Fermat's little theorem
--- @param out integer[] Output array
--- @param a integer[] Input array
local function fe_inv(out, a)
  local c = inv_c
  fe_copy(c, a)
  for i = 253, 0, -1 do
    fe_mul(c, c, c)
    if i ~= 2 and i ~= 4 then
      fe_mul(c, c, a)
    end
  end
  fe_copy(out, c)
end

--- Compute a^((p-5)/8), the candidate square root exponent used by decompression
--- @param out integer[] Output array
--- @param a integer[] Input array
local function fe_pow2523(out, a)
  local c = pow_c
  fe_copy(c, a)
  for i = 250, 0, -1 do
    fe_mul(c, c, c)
    if i ~= 1 then
      fe_mul(c, c, a)
    end
  end
  fe_copy(out, c)
end

--- Test two field elements for equality (compares canonical packed encodings)
--- @param a integer[] First field element
--- @param b integer[] Second field element
--- @return boolean equal True when a == b in the field
local function fe_eq(a, b)
  fe_pack(cmp_a, a)
  fe_pack(cmp_b, b)
  for i = 1, 32 do
    if cmp_a[i] ~= cmp_b[i] then
      return false
    end
  end
  return true
end

--- Return the least significant bit of the canonical encoding of a field element
--- @param a integer[] Input field element
--- @return integer parity 0 or 1
local function fe_parity(a)
  fe_pack(cmp_a, a)
  return bit32_raw_band(cmp_a[1], 1)
end

-- ============================================================================
-- EDWARDS25519 POINT ARITHMETIC (extended twisted Edwards coordinates)
-- ============================================================================

-- Curve constant d = -121665/121666 (mod 2^255-19)
local D = {
  0x78a3,
  0x1359,
  0x4dca,
  0x75eb,
  0xd8ab,
  0x4141,
  0x0a4d,
  0x0070,
  0xe898,
  0x7779,
  0x4079,
  0x8cc7,
  0xfe73,
  0x2b6f,
  0x6cee,
  0x5203,
}

-- 2*d (mod 2^255-19)
local D2 = {
  0xf159,
  0x26b2,
  0x9b94,
  0xebd6,
  0xb156,
  0x8283,
  0x149a,
  0x00e0,
  0xd130,
  0xeef3,
  0x80f2,
  0x198e,
  0xfce7,
  0x56df,
  0xd9dc,
  0x2406,
}

-- Base point x-coordinate
local BASE_X = {
  0xd51a,
  0x8f25,
  0x2d60,
  0xc956,
  0xa7b2,
  0x9525,
  0xc760,
  0x692c,
  0xdc5c,
  0xfdd6,
  0xe231,
  0xc0a4,
  0x53fe,
  0xcd6e,
  0x36d3,
  0x2169,
}

-- Base point y-coordinate (4/5)
local BASE_Y = {
  0x6658,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
  0x6666,
}

-- sqrt(-1) mod 2^255-19
local SQRT_M1 = {
  0xa0b0,
  0x4a0e,
  0x1b27,
  0xc4ee,
  0xe478,
  0xad2f,
  0x1806,
  0x2f43,
  0xd7a7,
  0x3dfb,
  0x0099,
  0x2b4d,
  0xdf0b,
  0x4fc1,
  0x2480,
  0x2b83,
}

local GF0 = create_field_element()
local GF1 = create_field_element()
GF1[1] = 1

-- Base point B in extended coordinates: (X, Y, 1, X*Y)
local BASE_POINT = create_point()
fe_copy(BASE_POINT[1], BASE_X)
fe_copy(BASE_POINT[2], BASE_Y)
fe_copy(BASE_POINT[3], GF1)
fe_mul(BASE_POINT[4], BASE_X, BASE_Y)

-- Pre-allocated scratch for pt_add()
local pa_a = create_field_element()
local pa_b = create_field_element()
local pa_c = create_field_element()
local pa_d = create_field_element()
local pa_e = create_field_element()
local pa_f = create_field_element()
local pa_g = create_field_element()
local pa_h = create_field_element()
local pa_t = create_field_element()

-- Pre-allocated scratch for pt_pack()
local pp_tx = create_field_element()
local pp_ty = create_field_element()
local pp_zi = create_field_element()

-- Pre-allocated scratch for pt_unpack_neg()
local un_t = create_field_element()
local un_chk = create_field_element()
local un_num = create_field_element()
local un_den = create_field_element()
local un_den2 = create_field_element()
local un_den4 = create_field_element()
local un_den6 = create_field_element()

-- Pre-allocated working points
local wp_p = create_point()
local wp_q = create_point()
local wp_r = create_point()
local wp_base = create_point()

--- Add two points in extended twisted Edwards coordinates: p := p + q
---
--- Safe to call with p == q (every coordinate is read before any is written).
--- @param p EdPoint Accumulator, overwritten with the sum
--- @param q EdPoint Point to add
local function pt_add(p, q)
  local a, b, c, d, e, f, g, h, t = pa_a, pa_b, pa_c, pa_d, pa_e, pa_f, pa_g, pa_h, pa_t
  fe_sub(a, p[2], p[1])
  fe_sub(t, q[2], q[1])
  fe_mul(a, a, t)
  fe_add(b, p[1], p[2])
  fe_add(t, q[1], q[2])
  fe_mul(b, b, t)
  fe_mul(c, p[4], q[4])
  fe_mul(c, c, D2)
  fe_mul(d, p[3], q[3])
  fe_add(d, d, d)
  fe_sub(e, b, a)
  fe_sub(f, d, c)
  fe_add(g, d, c)
  fe_add(h, b, a)

  fe_mul(p[1], e, f)
  fe_mul(p[2], h, g)
  fe_mul(p[3], g, f)
  fe_mul(p[4], e, h)
end

--- Conditionally swap two points based on a bit value (branch-free)
--- @param p EdPoint First point
--- @param q EdPoint Second point
--- @param bit integer Bit value (0 or 1)
local function pt_cswap(p, q, bit)
  for i = 1, 4 do
    fe_cswap(p[i], q[i], bit)
  end
end

--- Copy a point
--- @param out EdPoint Destination point
--- @param p EdPoint Source point
local function pt_copy(out, p)
  for i = 1, 4 do
    fe_copy(out[i], p[i])
  end
end

--- Compress a point into its 32-byte little-endian encoding
--- @param out integer[] Output byte array (32 bytes)
--- @param p EdPoint Point to compress
local function pt_pack(out, p)
  fe_inv(pp_zi, p[3])
  fe_mul(pp_tx, p[1], pp_zi)
  fe_mul(pp_ty, p[2], pp_zi)
  fe_pack(out, pp_ty)
  out[32] = bit32_raw_bxor(out[32], fe_parity(pp_tx) * 128)
end

--- Scalar multiplication: out := s * q (double-and-add over all 256 bits)
---
--- The base point argument `q` is destroyed by the conditional swaps.
--- @param out EdPoint Output point (must be a different table than q)
--- @param q EdPoint Input point, clobbered
--- @param s integer[] 32-byte little-endian scalar
local function pt_scalarmult(out, q, s)
  fe_copy(out[1], GF0)
  fe_copy(out[2], GF1)
  fe_copy(out[3], GF1)
  fe_copy(out[4], GF0)
  for i = 255, 0, -1 do
    local byte_idx = floor(i * 0.125) + 1 -- i / 8 + 1
    local bit = bit32_raw_band(bit32_raw_rshift(s[byte_idx], i % 8), 1)
    pt_cswap(out, q, bit)
    pt_add(q, out)
    pt_add(out, out)
    pt_cswap(out, q, bit)
  end
end

--- Scalar multiplication of the Ed25519 base point: out := s * B
--- @param out EdPoint Output point (must not be the shared base scratch point)
--- @param s integer[] 32-byte little-endian scalar
local function pt_scalarbase(out, s)
  pt_copy(wp_base, BASE_POINT)
  pt_scalarmult(out, wp_base, s)
end

--- Decompress a 32-byte encoding into the NEGATED point -(x, y)
---
--- Negating on decompression is what lets verification compute R + [k]A with a
--- single point addition (TweetNaCl's `unpackneg`).
--- @param out EdPoint Output point
--- @param p integer[] 32-byte encoded point
--- @return boolean ok False when the encoding is not a valid curve point
local function pt_unpack_neg(out, p)
  local t, chk, num, den = un_t, un_chk, un_num, un_den
  local den2, den4, den6 = un_den2, un_den4, un_den6

  fe_copy(out[3], GF1)
  fe_unpack(out[2], p)
  fe_sq(num, out[2])
  fe_mul(den, num, D)
  fe_sub(num, num, out[3])
  fe_add(den, out[3], den)

  fe_sq(den2, den)
  fe_sq(den4, den2)
  fe_mul(den6, den4, den2)
  fe_mul(t, den6, num)
  fe_mul(t, t, den)

  fe_pow2523(t, t)
  fe_mul(t, t, num)
  fe_mul(t, t, den)
  fe_mul(t, t, den)
  fe_mul(out[1], t, den)

  fe_sq(chk, out[1])
  fe_mul(chk, chk, den)
  if not fe_eq(chk, num) then
    fe_mul(out[1], out[1], SQRT_M1)
  end

  fe_sq(chk, out[1])
  fe_mul(chk, chk, den)
  if not fe_eq(chk, num) then
    return false
  end

  if fe_parity(out[1]) == bit32_raw_rshift(p[32], 7) then
    fe_sub(out[1], GF0, out[1])
  end

  fe_mul(out[4], out[1], out[2])
  return true
end

-- ============================================================================
-- SCALAR ARITHMETIC MODULO THE GROUP ORDER L
-- ============================================================================

-- L = 2^252 + 27742317777372353535851937790883648493, little-endian bytes
local L = {
  0xed,
  0xd3,
  0xf5,
  0x5c,
  0x1a,
  0x63,
  0x12,
  0x58,
  0xd6,
  0x9c,
  0xf7,
  0xa2,
  0xde,
  0xf9,
  0xde,
  0x14,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0x10,
}

-- Pre-allocated 64-limb accumulator for mod_l()
local modl_x = create_byte_array(64)

--- Reduce a 64-limb little-endian value modulo L, writing 32 bytes to `out`
---
--- Overflow bound: limbs stay under ~2^21 in magnitude, so the largest product
--- `16 * x[i] * L[j]` is below 16 * 2^21 * 2^8 = 2^33, far under 2^53.
--- @param out integer[] Output byte array (32 bytes)
--- @param x integer[] 64-limb accumulator, clobbered
local function mod_l(out, x)
  for i = 63, 32, -1 do
    local carry = 0
    local j = i - 32
    while j < i - 12 do
      x[j + 1] = x[j + 1] + carry - 16 * x[i + 1] * L[j - (i - 32) + 1]
      carry = floor((x[j + 1] + 128) * 0.00390625) -- (x + 128) >> 8
      x[j + 1] = x[j + 1] - carry * 256
      j = j + 1
    end
    x[j + 1] = x[j + 1] + carry
    x[i + 1] = 0
  end
  local carry = 0
  local top = floor(x[32] * 0.0625) -- x[31] >> 4
  for j = 0, 31 do
    x[j + 1] = x[j + 1] + carry - top * L[j + 1]
    carry = floor(x[j + 1] * 0.00390625)
    x[j + 1] = x[j + 1] % 256
  end
  for j = 0, 31 do
    x[j + 1] = x[j + 1] - carry * L[j + 1]
  end
  for i = 0, 31 do
    x[i + 2] = x[i + 2] + floor(x[i + 1] * 0.00390625)
    out[i + 1] = x[i + 1] % 256
  end
end

--- Reduce a 64-byte string modulo L
--- @param s string 64-byte little-endian value
--- @return integer[] scalar 32-byte reduced scalar as a byte array
local function reduce_hash(s)
  local x = modl_x
  for i = 1, 64 do
    x[i] = string_byte(s, i)
  end
  local out = create_byte_array(32)
  mod_l(out, x)
  return out
end

--- Compute (r + k * a) mod L
--- @param r integer[] 32-byte little-endian value
--- @param k integer[] 32-byte little-endian value
--- @param a integer[] 32-byte little-endian value
--- @return integer[] scalar 32-byte reduced result as a byte array
local function scalar_muladd(r, k, a)
  local x = modl_x
  for i = 1, 64 do
    x[i] = 0
  end
  for i = 1, 32 do
    x[i] = r[i]
  end
  for i = 1, 32 do
    local ki = k[i]
    if ki ~= 0 then
      for j = 1, 32 do
        x[i + j - 1] = x[i + j - 1] + ki * a[j]
      end
    end
  end
  local out = create_byte_array(32)
  mod_l(out, x)
  return out
end

--- Test whether a 32-byte little-endian scalar is strictly less than L
--- @param s integer[] 32-byte scalar
--- @return boolean canonical True when s < L
local function scalar_is_canonical(s)
  for i = 32, 1, -1 do
    if s[i] > L[i] then
      return false
    elseif s[i] < L[i] then
      return true
    end
  end
  return false -- s == L is not canonical either
end

-- ============================================================================
-- BYTE HELPERS
-- ============================================================================

--- Convert string to byte array
--- @param s string Input string
--- @param offset? integer 1-based offset into the string (default: 1)
--- @param len? integer Number of bytes to take (default: to end of string)
--- @return integer[] byte_array Byte array
local function string_to_bytes(s, offset, len)
  offset = offset or 1
  len = len or (#s - offset + 1)
  local b = {}
  for i = 1, len do
    b[i] = string_byte(s, offset + i - 1)
  end
  return b
end

--- Convert byte array to string
--- @param b integer[] Byte array
--- @param len integer Length
--- @return string result Output string
local function bytes_to_string(b, len)
  local result_bytes = {}
  for i = 1, len do
    result_bytes[i] = string_char(b[i] or 0)
  end
  return table_concat(result_bytes)
end

--- Apply the RFC 8032 clamping rules to the low half of SHA-512(seed)
--- @param a integer[] 32-byte scalar, modified in place
local function clamp(a)
  a[1] = bit32_raw_band(a[1], 248)
  a[32] = bit32_raw_bor(bit32_raw_band(a[32], 127), 64)
end

-- ============================================================================
-- ED25519 PUBLIC INTERFACE
-- ============================================================================

--- Generate a random Ed25519 private key (seed)
---
--- The seed is drawn from `crypto.random`, which raises rather than falling back
--- to a weak generator when the host has no CSPRNG. For Ed25519 that matters
--- more than for an ephemeral key: this seed is a long-term signing identity, so
--- a guessable one lets an attacker impersonate this device indefinitely.
--- @return string seed 32-byte private key seed
function ed25519.generate_private_key()
  return random.bytes(32)
end

--- Expand a 32-byte seed into the 64-byte signing key material
---
--- Returns `a || prefix` where `h = SHA-512(seed)`, `a = clamp(h[1..32])` and
--- `prefix = h[33..64]`. Callers that sign repeatedly with one long-term key can
--- cache this and use `sign_expanded` to skip the per-signature SHA-512(seed).
--- @param seed string 32-byte private key seed
--- @return string expanded 64-byte expanded key (clamped scalar || prefix)
function ed25519.expand_private_key(seed)
  assert(type(seed) == "string" and #seed == 32, "Seed must be exactly 32 bytes")

  local h = sha512(seed)
  local a = string_to_bytes(h, 1, 32)
  clamp(a)
  return bytes_to_string(a, 32) .. string_sub(h, 33, 64)
end

--- Derive the Ed25519 public key from a 32-byte seed
--- @param seed string 32-byte private key seed
--- @return string public_key 32-byte public key
function ed25519.derive_public_key(seed)
  assert(type(seed) == "string" and #seed == 32, "Seed must be exactly 32 bytes")

  local expanded = ed25519.expand_private_key(seed)
  local a = string_to_bytes(expanded, 1, 32)
  local pk = create_byte_array(32)

  pt_scalarbase(wp_p, a)
  pt_pack(pk, wp_p)
  return bytes_to_string(pk, 32)
end

--- Generate an Ed25519 key pair
--- @return string seed 32-byte private key seed
--- @return string public_key 32-byte public key
function ed25519.generate_keypair()
  local seed = ed25519.generate_private_key()
  local public_key = ed25519.derive_public_key(seed)
  return seed, public_key
end

--- Sign a message with a pre-expanded private key
---
--- Produces byte-identical output to `ed25519.sign` for the same key/message.
--- @param expanded string 64-byte expanded key from `expand_private_key`
--- @param public_key string 32-byte public key matching the expanded key
--- @param message string Message to sign (any length, may be empty)
--- @return string signature 64-byte signature (R || S)
function ed25519.sign_expanded(expanded, public_key, message)
  assert(type(expanded) == "string" and #expanded == 64, "Expanded key must be exactly 64 bytes")
  assert(type(public_key) == "string" and #public_key == 32, "Public key must be exactly 32 bytes")
  assert(type(message) == "string", "Message must be a string")

  local a = string_to_bytes(expanded, 1, 32)
  local prefix = string_sub(expanded, 33, 64)

  -- r = SHA-512(prefix || M) mod L, R = [r]B
  local r = reduce_hash(sha512(prefix .. message))
  local r_packed = create_byte_array(32)
  pt_scalarbase(wp_p, r)
  pt_pack(r_packed, wp_p)
  local r_str = bytes_to_string(r_packed, 32)

  -- k = SHA-512(R || A || M) mod L, S = (r + k * a) mod L
  local k = reduce_hash(sha512(r_str .. public_key .. message))
  local s = scalar_muladd(r, k, a)

  return r_str .. bytes_to_string(s, 32)
end

--- Sign a message with a 32-byte seed
--- @param seed string 32-byte private key seed
--- @param message string Message to sign (any length, may be empty)
--- @return string signature 64-byte signature (R || S)
function ed25519.sign(seed, message)
  assert(type(seed) == "string" and #seed == 32, "Seed must be exactly 32 bytes")
  assert(type(message) == "string", "Message must be a string")

  local expanded = ed25519.expand_private_key(seed)
  local a = string_to_bytes(expanded, 1, 32)
  local pk = create_byte_array(32)
  pt_scalarbase(wp_p, a)
  pt_pack(pk, wp_p)

  return ed25519.sign_expanded(expanded, bytes_to_string(pk, 32), message)
end

--- Verify an Ed25519 signature
---
--- Never raises: malformed public keys or signatures (wrong length, wrong type,
--- undecodable point, non-canonical S >= L) simply return false.
--- @param public_key string 32-byte public key
--- @param message string Signed message
--- @param signature string 64-byte signature (R || S)
--- @return boolean valid True when the signature is valid
function ed25519.verify(public_key, message, signature)
  if type(public_key) ~= "string" or type(message) ~= "string" or type(signature) ~= "string" then
    return false
  end
  if #public_key ~= 32 or #signature ~= 64 then
    return false
  end

  local s = string_to_bytes(signature, 33, 32)
  if not scalar_is_canonical(s) then
    return false
  end

  local pk = string_to_bytes(public_key, 1, 32)
  if not pt_unpack_neg(wp_q, pk) then
    return false
  end

  -- k = SHA-512(R || A || M) mod L
  local k = reduce_hash(sha512(string_sub(signature, 1, 32) .. public_key .. message))

  -- p = [k](-A) + [S]B, which must equal R
  pt_scalarmult(wp_p, wp_q, k)
  pt_scalarbase(wp_r, s)
  pt_add(wp_p, wp_r)

  local check = create_byte_array(32)
  pt_pack(check, wp_p)

  local diff = 0
  for i = 1, 32 do
    diff = bit32_raw_bor(diff, bit32_raw_bxor(check[i], string_byte(signature, i)))
  end
  return diff == 0
end

-- ============================================================================
-- TEST VECTORS AND VALIDATION
-- ============================================================================

--- Test vectors from RFC 8032 section 7.1 (Ed25519)
local test_vectors = {
  {
    name = "RFC 8032 TEST 1",
    seed = bytes.from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
    public_key = bytes.from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    message = "",
    signature = bytes.from_hex(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        .. "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ),
  },
  {
    name = "RFC 8032 TEST 2",
    seed = bytes.from_hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
    public_key = bytes.from_hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
    message = bytes.from_hex("72"),
    signature = bytes.from_hex(
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        .. "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    ),
  },
  {
    name = "RFC 8032 TEST 3",
    seed = bytes.from_hex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
    public_key = bytes.from_hex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
    message = bytes.from_hex("af82"),
    signature = bytes.from_hex(
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        .. "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    ),
  },
  {
    name = "RFC 8032 TEST 1024",
    seed = bytes.from_hex("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"),
    public_key = bytes.from_hex("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"),
    message = bytes.from_hex(
      "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
        .. "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
        .. "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
        .. "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
        .. "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
        .. "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
        .. "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
        .. "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
        .. "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
        .. "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
        .. "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
        .. "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
        .. "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
        .. "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
        .. "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
        .. "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
        .. "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
        .. "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
        .. "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
        .. "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
        .. "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
        .. "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
        .. "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
        .. "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
        .. "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
        .. "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
        .. "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
        .. "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
        .. "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
        .. "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
        .. "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
        .. "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"
    ),
    signature = bytes.from_hex(
      "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
        .. "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
    ),
  },
  {
    name = "RFC 8032 TEST SHA(abc)",
    seed = bytes.from_hex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"),
    public_key = bytes.from_hex("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"),
    message = bytes.from_hex(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        .. "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    ),
    signature = bytes.from_hex(
      "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
        .. "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
    ),
  },
}

--- Flip the low bit of one byte of a string (empty strings become a single NUL)
--- @param s string Input string
--- @param index integer 1-based byte index to tamper with
--- @return string tampered Tampered string, guaranteed different from the input
local function flip_bit(s, index)
  if #s == 0 then
    return "\0"
  end
  index = ((index - 1) % #s) + 1
  local b = bit32_raw_bxor(string_byte(s, index), 1)
  return string_sub(s, 1, index - 1) .. string_char(b) .. string_sub(s, index + 1)
end

--- Add the group order L to the 32-byte little-endian S half of a signature
--- @param signature string 64-byte signature
--- @return string tampered Signature whose S component equals S + L (>= L)
local function add_l_to_s(signature)
  local s = string_to_bytes(signature, 33, 32)
  local carry = 0
  for i = 1, 32 do
    local v = s[i] + L[i] + carry
    s[i] = v % 256
    carry = floor(v * 0.00390625)
  end
  return string_sub(signature, 1, 32) .. bytes_to_string(s, 32)
end

--- Run comprehensive self-test with RFC 8032 test vectors and functional tests
---
--- This function validates the Ed25519 implementation against the known-answer
--- test vectors from RFC 8032 section 7.1. ALL tests must pass for the
--- implementation to be considered cryptographically safe.
---
--- @return boolean result True if all tests pass, false otherwise
function ed25519.selftest()
  local function test_vectors_suite()
    print("Running Ed25519 test vectors...")
    local passed = 0
    local total = 0

    for i, test in ipairs(test_vectors) do
      print(string.format("Test %d: %s (message %d bytes)", i, test.name, #test.message))

      local checks = {}

      local derived = ed25519.derive_public_key(test.seed)
      checks[1] = { name = "derive_public_key", ok = derived == test.public_key, got = derived, want = test.public_key }

      local signature = ed25519.sign(test.seed, test.message)
      checks[2] = { name = "sign", ok = signature == test.signature, got = signature, want = test.signature }

      local expanded = ed25519.expand_private_key(test.seed)
      local sig_expanded = ed25519.sign_expanded(expanded, test.public_key, test.message)
      checks[3] = {
        name = "sign_expanded matches sign",
        ok = sig_expanded == test.signature and sig_expanded == signature,
        got = sig_expanded,
        want = test.signature,
      }

      checks[4] = {
        name = "verify accepts valid signature",
        ok = ed25519.verify(test.public_key, test.message, test.signature) == true,
      }
      checks[5] = {
        name = "verify rejects flipped message bit",
        ok = ed25519.verify(test.public_key, flip_bit(test.message, 1), test.signature) == false,
      }
      checks[6] = {
        name = "verify rejects flipped signature bit",
        ok = ed25519.verify(test.public_key, test.message, flip_bit(test.signature, 40)) == false,
      }

      for _, check in ipairs(checks) do
        total = total + 1
        if check.ok then
          print("  ✅ PASS: " .. check.name)
          passed = passed + 1
        else
          print("  ❌ FAIL: " .. check.name)
          if check.want then
            print("  Expected: " .. bytes.to_hex(check.want))
            print("  Got:      " .. bytes.to_hex(check.got))
          end
        end
      end
      print()
    end

    print(string.format("Test vectors result: %d/%d tests passed", passed, total))
    print()
    return passed == total
  end

  local function functional_tests()
    print("Running Ed25519 functional tests...")
    local passed = 0
    local total = 0

    local cases = {
      {
        name = "Key generation",
        test = function()
          local seed1, pub1 = ed25519.generate_keypair()
          local seed2, pub2 = ed25519.generate_keypair()
          assert(#seed1 == 32 and #pub1 == 32, "Keys should be 32 bytes")
          assert(seed1 ~= seed2, "Different key generations should produce different seeds")
          assert(pub1 ~= pub2, "Different key generations should produce different public keys")
        end,
      },
      {
        name = "Public key derivation consistency",
        test = function()
          local seed = ed25519.generate_private_key()
          assert(ed25519.derive_public_key(seed) == ed25519.derive_public_key(seed), "Derivation must be deterministic")
        end,
      },
      {
        name = "Expanded key shape and determinism",
        test = function()
          local seed = test_vectors[1].seed
          local expanded = ed25519.expand_private_key(seed)
          assert(#expanded == 64, "Expanded key should be 64 bytes")
          assert(expanded == ed25519.expand_private_key(seed), "Expansion must be deterministic")
          local a1 = string_byte(expanded, 1)
          local a32 = string_byte(expanded, 32)
          assert(a1 % 8 == 0, "Low 3 bits of the scalar must be cleared")
          assert(a32 < 128 and a32 >= 64, "Scalar must have bit 254 set and bit 255 cleared")
        end,
      },
      {
        name = "Sign/verify roundtrip with a generated key",
        test = function()
          local seed, pub = ed25519.generate_keypair()
          local msg = "The quick brown fox jumps over the lazy dog"
          local sig = ed25519.sign(seed, msg)
          assert(#sig == 64, "Signature should be 64 bytes")
          assert(ed25519.verify(pub, msg, sig) == true, "Signature should verify")
          assert(ed25519.verify(pub, msg .. "!", sig) == false, "Modified message must not verify")
        end,
      },
      {
        name = "sign_expanded is byte-identical to sign",
        test = function()
          local seed, pub = ed25519.generate_keypair()
          local expanded = ed25519.expand_private_key(seed)
          for _, msg in ipairs({ "", "a", string_rep("z", 200) }) do
            assert(ed25519.sign_expanded(expanded, pub, msg) == ed25519.sign(seed, msg), "Outputs must match")
          end
        end,
      },
      {
        name = "verify rejects a signature from another key",
        test = function()
          local seed_a = test_vectors[2].seed
          local _, pub_b = ed25519.generate_keypair()
          local msg = "cross-key check"
          assert(ed25519.verify(pub_b, msg, ed25519.sign(seed_a, msg)) == false, "Wrong key must not verify")
        end,
      },
      {
        name = "verify returns false for wrong-length signature",
        test = function()
          local v = test_vectors[3]
          assert(ed25519.verify(v.public_key, v.message, "") == false, "Empty signature must be rejected")
          assert(
            ed25519.verify(v.public_key, v.message, string_sub(v.signature, 1, 63)) == false,
            "Short signature must be rejected"
          )
          assert(ed25519.verify(v.public_key, v.message, v.signature .. "\0") == false, "Long signature is rejected")
        end,
      },
      {
        name = "verify returns false for wrong-length public key",
        test = function()
          local v = test_vectors[3]
          assert(ed25519.verify("", v.message, v.signature) == false, "Empty public key must be rejected")
          assert(
            ed25519.verify(string_sub(v.public_key, 1, 31), v.message, v.signature) == false,
            "Short public key must be rejected"
          )
          assert(ed25519.verify(v.public_key .. "\0", v.message, v.signature) == false, "Long public key is rejected")
        end,
      },
      {
        name = "verify returns false for undecodable public key",
        test = function()
          local v = test_vectors[3]
          -- y = 2 is not the y-coordinate of any edwards25519 point
          local bad = bytes.from_hex("0200000000000000000000000000000000000000000000000000000000000000")
          assert(ed25519.verify(bad, v.message, v.signature) == false, "Undecodable point must be rejected")
        end,
      },
      {
        name = "verify rejects non-canonical S >= L",
        test = function()
          local v = test_vectors[3]
          local malleable = add_l_to_s(v.signature)
          assert(malleable ~= v.signature, "Tampered signature should differ")
          assert(ed25519.verify(v.public_key, v.message, malleable) == false, "S >= L must be rejected")
        end,
      },
      {
        name = "verify returns false for non-string arguments",
        test = function()
          local v = test_vectors[3]
          assert(ed25519.verify(nil, v.message, v.signature) == false, "nil public key must be rejected")
          assert(ed25519.verify(v.public_key, nil, v.signature) == false, "nil message must be rejected")
          assert(ed25519.verify(v.public_key, v.message, 42) == false, "non-string signature must be rejected")
        end,
      },
    }

    for _, case in ipairs(cases) do
      total = total + 1
      local success, err = pcall(case.test)
      if success then
        print("  ✅ PASS: " .. case.name)
        passed = passed + 1
      else
        print("  ❌ FAIL: " .. case.name .. " - " .. tostring(err))
      end
    end

    print(string.format("\nFunctional tests result: %d/%d tests passed", passed, total))
    print()
    return passed == total
  end

  local vectors_passed = test_vectors_suite()
  local functional_passed = functional_tests()

  return vectors_passed and functional_passed
end

--- Run performance benchmarks
---
--- Benchmarks key pair generation, public key derivation, signing (both from a
--- raw seed and from a pre-expanded key) and verification.
function ed25519.benchmark()
  local vector = test_vectors[3]
  local seed = vector.seed
  local public_key = vector.public_key
  local message = vector.message
  local signature = vector.signature
  local expanded = ed25519.expand_private_key(seed)

  print("Key Operations:")
  benchmark_op("generate_keypair", function()
    ed25519.generate_keypair()
  end, 10)

  benchmark_op("derive_public_key", function()
    ed25519.derive_public_key(seed)
  end, 10)

  benchmark_op("expand_private_key", function()
    ed25519.expand_private_key(seed)
  end, 100)

  print("\nSignature Operations:")
  benchmark_op("sign", function()
    ed25519.sign(seed, message)
  end, 10)

  benchmark_op("sign_expanded", function()
    ed25519.sign_expanded(expanded, public_key, message)
  end, 10)

  benchmark_op("verify", function()
    ed25519.verify(public_key, message, signature)
  end, 10)
end

return ed25519
