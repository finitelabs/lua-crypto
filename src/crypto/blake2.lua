--- @module "crypto.blake2"
--- Pure Lua BLAKE2s and BLAKE2b Implementation for portability.
--- @class crypto.blake2
local blake2 = {}

local bitn = require("bitn")
local bit32 = bitn.bit32
local bit64 = bitn.bit64

local openssl_wrapper = require("crypto.openssl_wrapper")
local utils = require("crypto.utils")
local bytes = utils.bytes

-- Local references for performance
local bit32_raw_add = bit32.raw_add
local bit32_raw_bxor = bit32.raw_bxor
local bit32_raw_ror = bit32.raw_ror
local bit64_raw_add = bit64.raw_add
local bit64_raw_bxor = bit64.raw_bxor
local bit64_raw_ror = bit64.raw_ror
local bit64_new = bit64.new
local string_byte = string.byte
local string_char = string.char
local string_rep = string.rep
local table_concat = table.concat

-- BLAKE2s initialization vectors (first 32 bits of fractional parts of square roots of first 8 primes)
--- @type HashState
local BLAKE2S_IV = {
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
}

-- BLAKE2b initialization vectors (first 64 bits of fractional parts of square roots of first 8 primes)
--- @type HashState64
local BLAKE2B_IV = {
  { 0x6a09e667, 0xf3bcc908 },
  { 0xbb67ae85, 0x84caa73b },
  { 0x3c6ef372, 0xfe94f82b },
  { 0xa54ff53a, 0x5f1d36f1 },
  { 0x510e527f, 0xade682d1 },
  { 0x9b05688c, 0x2b3e6c1f },
  { 0x1f83d9ab, 0xfb41bd6b },
  { 0x5be0cd19, 0x137e2179 },
}

--- @alias Blake2sVector16 [integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer]
--- @alias Blake2bVector16 [Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow, Int64HighLow]

-- BLAKE2s permutation table
--- @type Blake2sVector16[]
local BLAKE2S_SIGMA = {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
  { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
  { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
  { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
  { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
}

-- BLAKE2b permutation table (same as BLAKE2s)
local BLAKE2B_SIGMA = BLAKE2S_SIGMA

--- Initialize a 16-element BLAKE2s working vector with zeros
--- @return Blake2sVector16 array Initialized array
local function create_blake2s_vector()
  local arr = {}
  for i = 1, 16 do
    arr[i] = 0
  end
  --- @cast arr Blake2sVector16
  return arr
end

--- Initialize a 16-element BLAKE2b working vector with zeros
--- @return Blake2bVector16 array Initialized array
local function create_blake2b_vector()
  local arr = {}
  for i = 1, 16 do
    arr[i] = bit64_new(0, 0)
  end
  --- @cast arr Blake2bVector16
  return arr
end

-- Pre-allocated arrays for blake2s_compress() to avoid repeated allocation
local blake2s_v = create_blake2s_vector()

-- Pre-allocated arrays for blake2b_compress() to avoid repeated allocation
local blake2b_v = create_blake2b_vector()

--- BLAKE2s G function
--- @param v Blake2sVector16 Working vector
--- @param a integer Index a
--- @param b integer Index b
--- @param c integer Index c
--- @param d integer Index d
--- @param x integer Message word x
--- @param y integer Message word y
local function blake2s_g(v, a, b, c, d, x, y)
  v[a] = bit32_raw_add(bit32_raw_add(v[a], v[b]), x)
  v[d] = bit32_raw_ror(bit32_raw_bxor(v[d], v[a]), 16)
  v[c] = bit32_raw_add(v[c], v[d])
  v[b] = bit32_raw_ror(bit32_raw_bxor(v[b], v[c]), 12)
  v[a] = bit32_raw_add(bit32_raw_add(v[a], v[b]), y)
  v[d] = bit32_raw_ror(bit32_raw_bxor(v[d], v[a]), 8)
  v[c] = bit32_raw_add(v[c], v[d])
  v[b] = bit32_raw_ror(bit32_raw_bxor(v[b], v[c]), 7)
end

--- BLAKE2b G function
--- @param v Blake2bVector16 Working vector
--- @param a integer Index a
--- @param b integer Index b
--- @param c integer Index c
--- @param d integer Index d
--- @param x table Message word x
--- @param y table Message word y
local function blake2b_g(v, a, b, c, d, x, y)
  v[a] = bit64_raw_add(bit64_raw_add(v[a], v[b]), x)
  v[d] = bit64_raw_ror(bit64_raw_bxor(v[d], v[a]), 32)
  v[c] = bit64_raw_add(v[c], v[d])
  v[b] = bit64_raw_ror(bit64_raw_bxor(v[b], v[c]), 24)
  v[a] = bit64_raw_add(bit64_raw_add(v[a], v[b]), y)
  v[d] = bit64_raw_ror(bit64_raw_bxor(v[d], v[a]), 16)
  v[c] = bit64_raw_add(v[c], v[d])
  v[b] = bit64_raw_ror(bit64_raw_bxor(v[b], v[c]), 63)
end

--- BLAKE2s compression function
--- @param h HashState Hash state (8 words)
--- @param m Blake2sVector16 Message block (16 words)
--- @param t integer Counter (low 32 bits)
--- @param th integer Counter (high 32 bits)
--- @param f boolean Final block flag
local function blake2s_compress(h, m, t, th, f)
  -- Reuse pre-allocated working vector
  local v = blake2s_v

  -- First half from hash state
  for i = 1, 8 do
    v[i] = h[i]
  end

  -- Second half from IV
  for i = 1, 8 do
    v[8 + i] = BLAKE2S_IV[i]
  end

  -- Mix in counter and final flag
  v[13] = bit32_raw_bxor(v[13], t) -- Low 32 bits of counter
  v[14] = bit32_raw_bxor(v[14], th) -- High 32 bits of counter
  if f then
    v[15] = bit32_raw_bxor(v[15], 0xFFFFFFFF) -- Invert all bits for final block
  end

  -- 10 rounds
  for r = 1, 10 do
    --- @type Blake2sVector16
    local s = assert(BLAKE2S_SIGMA[r], "Invalid BLAKE2s round index")

    -- Column step
    blake2s_g(v, 1, 5, 9, 13, m[s[1] + 1], m[s[2] + 1])
    blake2s_g(v, 2, 6, 10, 14, m[s[3] + 1], m[s[4] + 1])
    blake2s_g(v, 3, 7, 11, 15, m[s[5] + 1], m[s[6] + 1])
    blake2s_g(v, 4, 8, 12, 16, m[s[7] + 1], m[s[8] + 1])

    -- Diagonal step
    blake2s_g(v, 1, 6, 11, 16, m[s[9] + 1], m[s[10] + 1])
    blake2s_g(v, 2, 7, 12, 13, m[s[11] + 1], m[s[12] + 1])
    blake2s_g(v, 3, 8, 9, 14, m[s[13] + 1], m[s[14] + 1])
    blake2s_g(v, 4, 5, 10, 15, m[s[15] + 1], m[s[16] + 1])
  end

  -- Finalize
  for i = 1, 8 do
    h[i] = bit32_raw_bxor(bit32_raw_bxor(h[i], v[i]), v[i + 8])
  end
end

--- BLAKE2b compression function
--- @param h HashState64 Hash state (8 64-bit words)
--- @param m Blake2bVector16 Message block (16 64-bit words)
--- @param t table Counter (64-bit)
--- @param f boolean Final block flag
local function blake2b_compress(h, m, t, f)
  -- Reuse pre-allocated working vector
  local v = blake2b_v

  -- First half from hash state
  for i = 1, 8 do
    v[i][1], v[i][2] = h[i][1], h[i][2]
  end

  -- Second half from IV
  for i = 1, 8 do
    v[8 + i][1], v[8 + i][2] = BLAKE2B_IV[i][1], BLAKE2B_IV[i][2]
  end

  -- Mix in counter and final flag
  v[13] = bit64_raw_bxor(v[13], t)
  v[14] = bit64_raw_bxor(v[14], bit64_new(0, 0)) -- High 64 bits of counter (always 0 for messages < 2^64 bytes)
  if f then
    v[15] = bit64_raw_bxor(v[15], bit64_new(0xffffffff, 0xffffffff))
  end

  -- 12 rounds
  for r = 1, 12 do
    --- @type Blake2sVector16
    local s = assert(BLAKE2B_SIGMA[((r - 1) % 10) + 1], "Invalid round index for BLAKE2b")

    -- Column step
    blake2b_g(v, 1, 5, 9, 13, m[s[1] + 1], m[s[2] + 1])
    blake2b_g(v, 2, 6, 10, 14, m[s[3] + 1], m[s[4] + 1])
    blake2b_g(v, 3, 7, 11, 15, m[s[5] + 1], m[s[6] + 1])
    blake2b_g(v, 4, 8, 12, 16, m[s[7] + 1], m[s[8] + 1])

    -- Diagonal step
    blake2b_g(v, 1, 6, 11, 16, m[s[9] + 1], m[s[10] + 1])
    blake2b_g(v, 2, 7, 12, 13, m[s[11] + 1], m[s[12] + 1])
    blake2b_g(v, 3, 8, 9, 14, m[s[13] + 1], m[s[14] + 1])
    blake2b_g(v, 4, 5, 10, 15, m[s[15] + 1], m[s[16] + 1])
  end

  -- Finalize
  for i = 1, 8 do
    h[i] = bit64_raw_bxor(bit64_raw_bxor(h[i], v[i]), v[i + 8])
  end
end

--- Compute BLAKE2s hash of input data
--- @param data string Input data to hash
--- @return string hash 32-byte binary hash
function blake2.blake2s(data)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl then
    return openssl.digest.digest("blake2s256", data, true)
  end

  -- Native implementation
  -- Initialize hash state
  --- @type HashState
  local h = {}
  for i = 1, 8 do
    h[i] = BLAKE2S_IV[i]
  end

  -- Parameter block: digest length = 32, key length = 0, fanout = 1, depth = 1
  -- All other parameters are 0 (no salt, no personalization, etc.)
  local param = 32 + (0 * 256) + (1 * 65536) + (1 * 16777216) -- 0x01010020
  h[1] = bit32_raw_bxor(h[1], param)

  local data_len = #data
  local offset = 1
  local counter = 0

  -- Process full 64-byte blocks
  while offset + 63 <= data_len do
    counter = counter + 64

    -- Check if this is the last block
    local is_last_block = (offset + 64 > data_len)

    -- Load message block
    --- @type Blake2sVector16
    local m = {}
    for i = 1, 16 do
      m[i] = bytes.le_bytes_to_u32(data, offset + (i - 1) * 4)
    end

    blake2s_compress(h, m, counter, 0, is_last_block)
    offset = offset + 64
  end

  -- Process final block (if there's remaining data)
  local remaining = data_len - offset + 1

  if remaining > 0 then
    -- We have a partial block left to process
    counter = counter + remaining

    -- Pad final block with zeros
    local final_data = data:sub(offset)
    local final_block = final_data .. string_rep("\0", 64 - remaining)

    --- @type Blake2sVector16
    local m = {}
    for i = 1, 16 do
      m[i] = bytes.le_bytes_to_u32(final_block, (i - 1) * 4 + 1)
    end

    blake2s_compress(h, m, counter, 0, true)
  elseif data_len == 0 then
    -- Special case: empty input
    --- @type Blake2sVector16
    local m = {}
    for i = 1, 16 do
      m[i] = 0
    end

    blake2s_compress(h, m, 0, 0, true)
  end

  -- Produce final hash value as binary string (optimized with table)
  local result_bytes = {}
  for i = 1, 8 do
    result_bytes[i] = bytes.u32_to_le_bytes(h[i])
  end

  return table_concat(result_bytes)
end

--- Compute BLAKE2b hash of input data
--- @param data string Input data to hash
--- @return string hash 64-byte binary hash
function blake2.blake2b(data)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl then
    return openssl.digest.digest("blake2b512", data, true)
  end

  -- Native implementation
  -- Initialize hash state
  --- @type HashState64
  local h = {}
  for i = 1, 8 do
    h[i] = { BLAKE2B_IV[i][1], BLAKE2B_IV[i][2] }
  end

  -- Parameter block: digest length = 64, key length = 0, fanout = 1, depth = 1
  -- The parameter block is 128 bytes, but we only need to XOR the first 8 bytes with h[1]
  -- Format (little-endian): digest_length(1) || key_length(1) || fanout(1) || depth(1) || leaf_length(4)
  -- For standard BLAKE2b: digest_length=64, key_length=0, fanout=1, depth=1
  -- In little-endian 64-bit: 0x0000000001010040
  -- Split into two 32-bit words (little-endian): low=0x01010040, high=0x00000000
  -- But our u64 format is {high, low}, so we need {0x00000000, 0x01010040}
  h[1] = bit64_raw_bxor(h[1], bit64_new(0x00000000, 0x01010040))

  local data_len = #data
  local offset = 1
  local counter = bit64_new(0, 0)

  -- Process full 128-byte blocks
  while offset + 127 <= data_len do
    counter = bit64_raw_add(counter, bit64_new(0, 128))

    -- Check if this is the last block
    local is_last_block = (offset + 128 > data_len)

    -- Load message block
    --- @type Blake2bVector16
    local m = {}
    for i = 1, 16 do
      m[i] = bytes.le_bytes_to_u64(data, offset + (i - 1) * 8)
    end

    blake2b_compress(h, m, counter, is_last_block)
    offset = offset + 128
  end

  -- Process final block (if there's remaining data)
  local remaining = data_len - offset + 1
  if remaining > 0 then
    counter = bit64_raw_add(counter, bit64_new(0, remaining))

    -- Pad final block with zeros
    local final_block = data:sub(offset) .. string_rep("\0", 128 - remaining)

    --- @type Blake2bVector16
    local m = {}
    for i = 1, 16 do
      m[i] = bytes.le_bytes_to_u64(final_block, (i - 1) * 8 + 1)
    end

    blake2b_compress(h, m, counter, true)
  elseif data_len == 0 then
    -- Empty input case
    --- @type Blake2bVector16
    local m = {}
    for i = 1, 16 do
      m[i] = bit64_new(0, 0)
    end
    blake2b_compress(h, m, bit64_new(0, 0), true)
  end

  -- Produce final hash value as binary string (optimized with table)
  local result_bytes = {}
  for i = 1, 8 do
    result_bytes[i] = bytes.u64_to_le_bytes(h[i])
  end

  return table_concat(result_bytes)
end

--- Compute BLAKE2s hash and return as hex string
--- @param data string Input data to hash
--- @return string hex 64-character hex string
function blake2.blake2s_hex(data)
  return bytes.to_hex(blake2.blake2s(data))
end

--- Compute BLAKE2b hash and return as hex string
--- @param data string Input data to hash
--- @return string hex 128-character hex string
function blake2.blake2b_hex(data)
  return bytes.to_hex(blake2.blake2b(data))
end

--- Compute HMAC-BLAKE2s
--- Note: RFC 7693 recommends using BLAKE2's native keyed mode instead of HMAC.
--- However, HMAC-BLAKE2 is provided for compatibility with protocols that require
--- HMAC for all hash functions (e.g., Noise Protocol Framework).
--- @param key string Secret key
--- @param data string Data to authenticate
--- @return string hmac 32-byte HMAC value
function blake2.hmac_blake2s(key, data)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl then
    return openssl.hmac.hmac("blake2s256", data, key, true)
  end

  -- Native implementation
  local block_size = 64 -- BLAKE2s block size

  -- Keys longer than blocksize are shortened by hashing them
  if #key > block_size then
    key = blake2.blake2s(key)
  end

  -- Keys shorter than blocksize are right-padded with zeros
  if #key < block_size then
    key = key .. string_rep("\0", block_size - #key)
  end

  -- Compute inner and outer padding (optimized with table)
  local ipad_bytes = {}
  local opad_bytes = {}
  for i = 1, block_size do
    local byte = string_byte(key, i)
    ipad_bytes[i] = string_char(bit32_raw_bxor(byte, 0x36))
    opad_bytes[i] = string_char(bit32_raw_bxor(byte, 0x5C))
  end
  local ipad = table_concat(ipad_bytes)
  local opad = table_concat(opad_bytes)

  -- Compute HMAC = H(opad || H(ipad || data))
  local inner_hash = blake2.blake2s(ipad .. data)
  return blake2.blake2s(opad .. inner_hash)
end

--- Compute HMAC-BLAKE2b
--- Note: RFC 7693 recommends using BLAKE2's native keyed mode instead of HMAC.
--- However, HMAC-BLAKE2 is provided for compatibility with protocols that require
--- HMAC for all hash functions (e.g., Noise Protocol Framework).
--- @param key string Secret key
--- @param data string Data to authenticate
--- @return string hmac 64-byte HMAC value
function blake2.hmac_blake2b(key, data)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl then
    return openssl.hmac.hmac("blake2b512", data, key, true)
  end

  -- Native implementation
  local block_size = 128 -- BLAKE2b block size

  -- Keys longer than blocksize are shortened by hashing them
  if #key > block_size then
    key = blake2.blake2b(key)
  end

  -- Keys shorter than blocksize are right-padded with zeros
  if #key < block_size then
    key = key .. string_rep("\0", block_size - #key)
  end

  -- Compute inner and outer padding (optimized with table)
  local ipad_bytes = {}
  local opad_bytes = {}
  for i = 1, block_size do
    local byte = string_byte(key, i)
    ipad_bytes[i] = string_char(bit32_raw_bxor(byte, 0x36))
    opad_bytes[i] = string_char(bit32_raw_bxor(byte, 0x5C))
  end
  local ipad = table_concat(ipad_bytes)
  local opad = table_concat(opad_bytes)

  -- Compute HMAC = H(opad || H(ipad || data))
  local inner_hash = blake2.blake2b(ipad .. data)
  return blake2.blake2b(opad .. inner_hash)
end

--- Compute HMAC-BLAKE2s and return as hex string
--- @param key string Secret key
--- @param data string Data to authenticate
--- @return string hex 64-character hex string
function blake2.hmac_blake2s_hex(key, data)
  return bytes.to_hex(blake2.hmac_blake2s(key, data))
end

--- Compute HMAC-BLAKE2b and return as hex string
--- @param key string Secret key
--- @param data string Data to authenticate
--- @return string hex 128-character hex string
function blake2.hmac_blake2b_hex(key, data)
  return bytes.to_hex(blake2.hmac_blake2b(key, data))
end

return blake2
