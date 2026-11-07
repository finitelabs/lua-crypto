--- @module "crypto.sha256"
--- Pure Lua SHA-256 Implementation for portability.
--- @class crypto.sha256
local sha256 = {}

local bit32 = require("bitn").bit32

local openssl_wrapper = require("crypto.openssl_wrapper")
local utils = require("crypto.utils")
local bytes = utils.bytes

-- Local references for performance
local bit32_raw_bxor = bit32.raw_bxor
local bit32_raw_band = bit32.raw_band
local bit32_raw_bnot = bit32.raw_bnot
local bit32_raw_ror = bit32.raw_ror
local bit32_raw_rshift = bit32.raw_rshift
local bit32_raw_add = bit32.raw_add
local bytes_be_bytes_to_u32 = bytes.be_bytes_to_u32
local bytes_u32_to_be_bytes = bytes.u32_to_be_bytes
local string_char = string.char
local string_rep = string.rep
local string_byte = string.byte
local table_concat = table.concat

-- SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
--- @type integer[64]
local K = {
  0x428a2f98,
  0x71374491,
  0xb5c0fbcf,
  0xe9b5dba5,
  0x3956c25b,
  0x59f111f1,
  0x923f82a4,
  0xab1c5ed5,
  0xd807aa98,
  0x12835b01,
  0x243185be,
  0x550c7dc3,
  0x72be5d74,
  0x80deb1fe,
  0x9bdc06a7,
  0xc19bf174,
  0xe49b69c1,
  0xefbe4786,
  0x0fc19dc6,
  0x240ca1cc,
  0x2de92c6f,
  0x4a7484aa,
  0x5cb0a9dc,
  0x76f988da,
  0x983e5152,
  0xa831c66d,
  0xb00327c8,
  0xbf597fc7,
  0xc6e00bf3,
  0xd5a79147,
  0x06ca6351,
  0x14292967,
  0x27b70a85,
  0x2e1b2138,
  0x4d2c6dfc,
  0x53380d13,
  0x650a7354,
  0x766a0abb,
  0x81c2c92e,
  0x92722c85,
  0xa2bfe8a1,
  0xa81a664b,
  0xc24b8b70,
  0xc76c51a3,
  0xd192e819,
  0xd6990624,
  0xf40e3585,
  0x106aa070,
  0x19a4c116,
  0x1e376c08,
  0x2748774c,
  0x34b0bcb5,
  0x391c0cb3,
  0x4ed8aa4a,
  0x5b9cca4f,
  0x682e6ff3,
  0x748f82ee,
  0x78a5636f,
  0x84c87814,
  0x8cc70208,
  0x90befffa,
  0xa4506ceb,
  0xbef9a3f7,
  0xc67178f2,
}

--- @alias HashState [integer, integer, integer, integer, integer, integer, integer, integer]

-- Initial SHA-256 hash values (first 32 bits of fractional parts of square roots of first 8 primes)
--- @type HashState
local H0 = {
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
}

--- Initialize a 64-element message schedule array with zeros
--- @return integer[] array Initialized array
local function create_message_schedule()
  local arr = {}
  for i = 1, 64 do
    arr[i] = 0
  end
  return arr
end

-- Pre-allocated message schedule array for sha256_chunk()
local chunk_W = create_message_schedule()

--- SHA-256 core compression function
--- @param chunk string 64-byte chunk
--- @param H HashState Hash state (8 integers)
local function sha256_chunk(chunk, H)
  -- Reuse pre-allocated message schedule W
  local W = chunk_W

  -- First 16 words are the message chunk (use local reference)
  for i = 1, 16 do
    W[i] = bytes_be_bytes_to_u32(chunk, (i - 1) * 4 + 1)
  end

  -- Extend the first 16 words into the remaining 48 words
  for i = 17, 64 do
    local w15 = W[i - 15]
    local w2 = W[i - 2]
    local s0 = bit32_raw_bxor(bit32_raw_ror(w15, 7), bit32_raw_bxor(bit32_raw_ror(w15, 18), bit32_raw_rshift(w15, 3)))
    local s1 = bit32_raw_bxor(bit32_raw_ror(w2, 17), bit32_raw_bxor(bit32_raw_ror(w2, 19), bit32_raw_rshift(w2, 10)))
    W[i] = bit32_raw_add(bit32_raw_add(bit32_raw_add(W[i - 16], s0), W[i - 7]), s1)
  end

  -- Initialize working variables
  local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]

  -- Main loop (optimized with local references)
  for i = 1, 64 do
    local ki = K[i]
    local S1 = bit32_raw_bxor(bit32_raw_ror(e, 6), bit32_raw_bxor(bit32_raw_ror(e, 11), bit32_raw_ror(e, 25)))
    local ch = bit32_raw_bxor(bit32_raw_band(e, f), bit32_raw_band(bit32_raw_bnot(e), g))
    local temp1 = bit32_raw_add(bit32_raw_add(bit32_raw_add(bit32_raw_add(h, S1), ch), ki), W[i])
    local S0 = bit32_raw_bxor(bit32_raw_ror(a, 2), bit32_raw_bxor(bit32_raw_ror(a, 13), bit32_raw_ror(a, 22)))
    local maj = bit32_raw_bxor(bit32_raw_band(a, b), bit32_raw_bxor(bit32_raw_band(a, c), bit32_raw_band(b, c)))
    local temp2 = bit32_raw_add(S0, maj)

    h = g
    g = f
    f = e
    e = bit32_raw_add(d, temp1)
    d = c
    c = b
    b = a
    a = bit32_raw_add(temp1, temp2)
  end

  -- Add compressed chunk to current hash value
  H[1] = bit32_raw_add(H[1], a)
  H[2] = bit32_raw_add(H[2], b)
  H[3] = bit32_raw_add(H[3], c)
  H[4] = bit32_raw_add(H[4], d)
  H[5] = bit32_raw_add(H[5], e)
  H[6] = bit32_raw_add(H[6], f)
  H[7] = bit32_raw_add(H[7], g)
  H[8] = bit32_raw_add(H[8], h)
end

-- ============================================================================
-- SHA-256 PUBLIC INTERFACE
-- ============================================================================

--- Compute SHA-256 hash of input data
--- @param data string Input data to hash
--- @return string hash 32-byte binary hash
function sha256.sha256(data)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl then
    return openssl.digest.digest("sha256", data, true)
  end

  -- Native implementation
  -- Initialize hash values
  --- @type HashState
  local H = { H0[1], H0[2], H0[3], H0[4], H0[5], H0[6], H0[7], H0[8] }

  -- Pre-processing: adding padding bits
  local msg_len = #data
  local msg_len_bits = msg_len * 8

  -- Append '1' bit (plus zero padding to make it a byte)
  data = data .. string_char(0x80)

  -- Append zeros to make message length ≡ 448 (mod 512) bits = 56 (mod 64) bytes
  -- Current length is msg_len + 1 (for the 0x80 byte)
  local current_len = msg_len + 1
  local target_len = 56 -- We want to reach 56 bytes before adding the 8-byte length
  local padding_len = (target_len - current_len) % 64
  data = data .. string_rep("\0", padding_len)

  -- Append original length as 64-bit big-endian integer
  -- For simplicity, we only support messages < 2^32 bits
  data = data .. string_rep("\0", 4) .. bytes_u32_to_be_bytes(msg_len_bits)

  -- Process message in 64-byte chunks
  for i = 1, #data, 64 do
    local chunk = data:sub(i, i + 63)
    if #chunk == 64 then
      sha256_chunk(chunk, H)
    end
  end

  -- Produce final hash value as binary string (optimized with table)
  local result_bytes = {}
  for i = 1, 8 do
    result_bytes[i] = bytes_u32_to_be_bytes(H[i])
  end

  return table_concat(result_bytes)
end

--- Compute SHA-256 hash and return as hex string
--- @param data string Input data to hash
--- @return string hex 64-character hex string
function sha256.sha256_hex(data)
  local hash = sha256.sha256(data)
  return bytes.to_hex(hash)
end

--- Compute HMAC-SHA256
--- @param key string Secret key
--- @param data string Data to authenticate
--- @return string hmac 32-byte HMAC value
function sha256.hmac_sha256(key, data)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl then
    return openssl.hmac.hmac("sha256", data, key, true)
  end

  -- Native implementation
  local block_size = 64 -- SHA-256 block size

  -- Keys longer than blocksize are shortened by hashing them
  if #key > block_size then
    key = sha256.sha256(key)
  end

  -- Keys shorter than blocksize are right-padded with zeros
  if #key < block_size then
    key = key .. string_rep("\0", block_size - #key)
  end

  -- Compute inner and outer padding (optimized with local references)
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
  local inner_hash = sha256.sha256(ipad .. data)
  return sha256.sha256(opad .. inner_hash)
end

--- Compute HMAC-SHA256 and return as hex string
--- @param key string Secret key
--- @param data string Data to authenticate
--- @return string hex 64-character hex string
function sha256.hmac_sha256_hex(key, data)
  local hmac = sha256.hmac_sha256(key, data)
  return bytes.to_hex(hmac)
end

return sha256
