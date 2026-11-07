--- @module "crypto.x25519"
--- X25519 Curve25519 Elliptic Curve Diffie-Hellman Implementation for portability.
--- @class crypto.x25519
local x25519 = {}

local bit32 = require("bitn").bit32

local random = require("crypto.random")

-- Local references for performance
local bit32_raw_band = bit32.raw_band
local bit32_raw_rshift = bit32.raw_rshift
local floor = math.floor
local string_byte = string.byte
local string_char = string.char
local table_concat = table.concat

-- ============================================================================
-- CURVE25519 FIELD ARITHMETIC
-- ============================================================================

-- `FieldElement` and `ProductArray` are shared with ed25519 (same field, same
-- limb layout) and are defined once in `annotations.lua`.

--- @alias ScalarArray integer[] 32-element array (indices 1-32) for scalar bytes

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

--- Initialize a 32-element scalar array with zeros
--- @return ScalarArray arr Initialized array
local function create_scalar_array()
  local arr = {}
  for i = 1, 32 do
    arr[i] = 0
  end
  return arr
end

-- Pre-allocated constant for Montgomery ladder (a24 = 121665 = 0xdb41 + 1*0x10000)
-- This is (A-2)/4 where A=486662 for Curve25519
local A24 = { 0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }

-- Pre-allocated product array for mul() to avoid repeated allocation
local mul_prod = create_product_array()

-- Pre-allocated arrays for pack() to avoid repeated allocation
local pack_t = create_field_element()
local pack_m = create_field_element()

-- Pre-allocated arrays for inv() to avoid repeated allocation
local inv_c = create_field_element()

-- Pre-allocated arrays for scalarmult() Montgomery ladder
-- These are the most critical - 8 arrays created per DH operation
local sm_a = create_field_element()
local sm_b = create_field_element()
local sm_c = create_field_element()
local sm_d = create_field_element()
local sm_e = create_field_element()
local sm_f = create_field_element()
local sm_x = create_field_element()
local sm_clam = create_scalar_array()

--- Carry operation for 64-bit arithmetic
--- @param out integer[] Array to perform carry on
local function carry(out)
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

--- Conditional swap based on bit value
--- @param a integer[] First array
--- @param b integer[] Second array
--- @param bit integer Bit value (0 or 1)
local function swap(a, b, bit)
  for i = 1, 16 do
    a[i], b[i] = a[i] * ((bit - 1) % 2) + b[i] * bit, b[i] * ((bit - 1) % 2) + a[i] * bit
  end
end

--- Unpack byte array to limb array
--- @param out integer[] Output limb array
--- @param a integer[] Input byte array
local function unpack(out, a)
  for i = 1, 16 do
    out[i] = a[2 * i - 1] + a[2 * i] * 0x100
  end
  out[16] = out[16] % 0x8000
end

-- Pre-allocated prime constant for pack()
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

--- Pack limb array to byte array with modular reduction
--- @param out integer[] Output byte array
--- @param a integer[] Input limb array
local function pack(out, a)
  -- Reuse pre-allocated arrays
  local t, m = pack_t, pack_m
  for i = 1, 16 do
    t[i] = a[i]
  end
  carry(t)
  carry(t)
  carry(t)
  for _ = 1, 2 do
    m[1] = t[1] - PRIME[1]
    for i = 2, 16 do
      local prev = m[i - 1]
      m[i] = t[i] - PRIME[i] - (floor(prev * 0.0000152587890625) % 2)
      m[i - 1] = (prev + 0x10000) % 0x10000
    end
    local c = floor(m[16] * 0.0000152587890625) % 2
    swap(t, m, 1 - c)
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
local function add(out, a, b)
  for i = 1, 16 do
    out[i] = a[i] + b[i]
  end
end

--- Subtract two field elements
--- @param out integer[] Output array
--- @param a integer[] First input array
--- @param b integer[] Second input array
local function sub(out, a, b)
  for i = 1, 16 do
    out[i] = a[i] - b[i]
  end
end

--- Multiply two field elements
--- @param out integer[] Output array
--- @param a integer[] First input array
--- @param b integer[] Second input array
local function mul(out, a, b)
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
  carry(out)
  carry(out)
end

--- Compute modular inverse using Fermat's little theorem
--- @param out integer[] Output array
--- @param a integer[] Input array
local function inv(out, a)
  -- Reuse pre-allocated array
  local c = inv_c
  for i = 1, 16 do
    c[i] = a[i]
  end
  for i = 253, 0, -1 do
    mul(c, c, c)
    if i ~= 2 and i ~= 4 then
      mul(c, c, a)
    end
  end
  for i = 1, 16 do
    out[i] = c[i]
  end
end

--- X25519 scalar multiplication using Montgomery ladder
--- @param out integer[] Output point
--- @param scalar integer[] Input scalar
--- @param point integer[] Input point
local function scalarmult(out, scalar, point)
  -- Reuse pre-allocated arrays for Montgomery ladder state
  local a, b, c, d, e, f, x, clam = sm_a, sm_b, sm_c, sm_d, sm_e, sm_f, sm_x, sm_clam
  unpack(x, point)
  for i = 1, 16 do
    a[i], b[i], c[i], d[i] = 0, x[i], 0, 0
  end
  a[1], d[1] = 1, 1
  for i = 1, 31 do
    clam[i] = scalar[i]
  end
  clam[1] = clam[1] - (clam[1] % 8)
  clam[32] = scalar[32] % 64 + 64
  for i = 254, 0, -1 do
    -- Optimized bit extraction
    local byte_idx = floor(i * 0.125) + 1 -- i / 8 + 1
    local bit_idx = i % 8
    local bit = bit32_raw_band(bit32_raw_rshift(clam[byte_idx], bit_idx), 1)
    swap(a, b, bit)
    swap(c, d, bit)
    add(e, a, c)
    sub(a, a, c)
    add(c, b, d)
    sub(b, b, d)
    mul(d, e, e)
    mul(f, a, a)
    mul(a, c, a)
    mul(c, b, e)
    add(e, a, c)
    sub(a, a, c)
    mul(b, a, a)
    sub(c, d, f)
    mul(a, c, A24) -- Use pre-allocated constant
    add(a, a, d)
    mul(c, c, a)
    mul(a, d, f)
    mul(d, b, x)
    mul(b, e, e)
    swap(a, b, bit)
    swap(c, d, bit)
  end
  inv(c, c)
  mul(a, a, c)
  pack(out, a)
end

--- Convert string to byte array
--- @param s string Input string
--- @return integer[] byte_array Byte array
local function string_to_bytes(s)
  local b = {}
  for i = 1, #s do
    b[i] = string_byte(s, i)
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

-- ============================================================================
-- X25519 PUBLIC INTERFACE
-- ============================================================================

--- Generate a random Curve25519 private key
---
--- Drawn from `crypto.random`, which raises rather than falling back to a weak
--- generator when the host has no CSPRNG. A guessable ephemeral scalar here
--- yields the shared secret to anyone who observed the exchange.
--- @return string private_key 32-byte private key
function x25519.generate_private_key()
  return random.bytes(32)
end

--- Derive public key from private key
--- @param private_key string 32-byte private key
--- @return string public_key 32-byte public key
function x25519.derive_public_key(private_key)
  assert(#private_key == 32, "Private key must be exactly 32 bytes")

  local sk = string_to_bytes(private_key)
  local pk = {}
  local base = { 9 }
  for i = 2, 32 do
    base[i] = 0
  end

  scalarmult(pk, sk, base)
  return bytes_to_string(pk, 32)
end

--- Perform X25519 Diffie-Hellman
--- @param private_key string 32-byte private key
--- @param public_key string 32-byte public key
--- @return string shared_secret 32-byte shared secret
function x25519.diffie_hellman(private_key, public_key)
  assert(#private_key == 32, "Private key must be exactly 32 bytes")
  assert(#public_key == 32, "Public key must be exactly 32 bytes")

  local sk = string_to_bytes(private_key)
  local pk = string_to_bytes(public_key)
  local shared = {}

  scalarmult(shared, sk, pk)
  return bytes_to_string(shared, 32)
end

--- Generate a Curve25519 key pair
--- @return string private_key 32-byte private key
--- @return string public_key 32-byte public key
function x25519.generate_keypair()
  local private_key = x25519.generate_private_key()
  local public_key = x25519.derive_public_key(private_key)
  return private_key, public_key
end

return x25519
