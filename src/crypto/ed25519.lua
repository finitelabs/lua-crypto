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

-- Local references for performance
local bit32_raw_band = bit32.raw_band
local bit32_raw_bor = bit32.raw_bor
local bit32_raw_bxor = bit32.raw_bxor
local bit32_raw_rshift = bit32.raw_rshift
local floor = math.floor
local sha512 = sha512_mod.sha512
local string_byte = string.byte
local string_char = string.char
local string_sub = string.sub
local table_concat = table.concat

-- ============================================================================
-- CURVE25519 FIELD ARITHMETIC (shared field with X25519: p = 2^255 - 19)
-- ============================================================================

-- `FieldElement` and `ProductArray` are shared with x25519 (same field, same
-- limb layout) and are defined once in `annotations.lua`.

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

-- Private functions and values the tests in test/ check directly.
ed25519._internal = {
  string_to_bytes = string_to_bytes,
  bytes_to_string = bytes_to_string,
}

return ed25519
