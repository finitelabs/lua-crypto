--- @module "crypto.chacha20"
--- ChaCha20 Stream Cipher Implementation for portability.
--- @class crypto.chacha20
local chacha20 = {}

local bit32 = require("bitn").bit32

local openssl_wrapper = require("crypto.openssl_wrapper")
local utils = require("crypto.utils")
local bytes = utils.bytes

-- Local references for performance
local bit32_raw_add = bit32.raw_add
local bit32_raw_bxor = bit32.raw_bxor
local bit32_raw_rol = bit32.raw_rol
local bit32_u32_to_le_bytes = bit32.u32_to_le_bytes
local bit32_le_bytes_to_u32 = bit32.le_bytes_to_u32
local min = math.min
local string_byte = string.byte
local string_char = string.char
local table_concat = table.concat

-- Type definitions for better type checking

--- 16-element array of 32-bit words
--- @class Word32Array
--- @field [1] integer
--- @field [2] integer
--- @field [3] integer
--- @field [4] integer
--- @field [5] integer
--- @field [6] integer
--- @field [7] integer
--- @field [8] integer
--- @field [9] integer
--- @field [10] integer
--- @field [11] integer
--- @field [12] integer
--- @field [13] integer
--- @field [14] integer
--- @field [15] integer
--- @field [16] integer

--- Initialize a 16-element word array with zeros
--- @return Word32Array array Initialized array
local function create_word_array()
  local arr = {}
  for i = 1, 16 do
    arr[i] = 0
  end
  --- @cast arr Word32Array
  return arr
end

-- Pre-allocated arrays for chacha20_block() to avoid repeated allocation
local block_state = create_word_array()
local block_working = create_word_array()

--- ChaCha20 quarter round operation
--- @param state Word32Array 16-word state array (modified in place)
--- @param a integer Index of first word
--- @param b integer Index of second word
--- @param c integer Index of third word
--- @param d integer Index of fourth word
local function quarter_round(state, a, b, c, d)
  state[a] = bit32_raw_add(state[a], state[b])
  state[d] = bit32_raw_rol(bit32_raw_bxor(state[d], state[a]), 16)

  state[c] = bit32_raw_add(state[c], state[d])
  state[b] = bit32_raw_rol(bit32_raw_bxor(state[b], state[c]), 12)

  state[a] = bit32_raw_add(state[a], state[b])
  state[d] = bit32_raw_rol(bit32_raw_bxor(state[d], state[a]), 8)

  state[c] = bit32_raw_add(state[c], state[d])
  state[b] = bit32_raw_rol(bit32_raw_bxor(state[b], state[c]), 7)
end

--- Generate one 64-byte block of ChaCha20 keystream
--- @param key string 32-byte key
--- @param nonce string 12-byte nonce
--- @param counter integer 32-bit counter value
--- @return string keystream 64-byte keystream block
local function chacha20_block(key, nonce, counter)
  -- Reuse pre-allocated arrays
  local state = block_state
  local working_state = block_working

  -- Initialize state inline (avoiding function call overhead)
  assert(#key == 32, "Key must be exactly 32 bytes")
  assert(#nonce == 12, "Nonce must be exactly 12 bytes")
  assert(counter >= 0 and counter < 0x100000000, "Counter must be a valid 32-bit integer")

  -- ChaCha20 constants "expand 32-byte k"
  state[1] = 0x61707865 -- "expa"
  state[2] = 0x3320646e -- "nd 3"
  state[3] = 0x79622d32 -- "2-by"
  state[4] = 0x6b206574 -- "te k"

  -- 256-bit key (8 words)
  for i = 1, 8 do
    state[4 + i] = bit32_le_bytes_to_u32(key, (i - 1) * 4 + 1)
  end

  -- 32-bit counter
  state[13] = counter

  -- 96-bit nonce (3 words)
  for i = 1, 3 do
    state[13 + i] = bit32_le_bytes_to_u32(nonce, (i - 1) * 4 + 1)
  end

  -- Create working copy of state
  for i = 1, 16 do
    working_state[i] = state[i]
  end

  -- Perform 20 rounds (10 double rounds)
  for _ = 1, 10 do
    -- Column rounds
    quarter_round(working_state, 1, 5, 9, 13)
    quarter_round(working_state, 2, 6, 10, 14)
    quarter_round(working_state, 3, 7, 11, 15)
    quarter_round(working_state, 4, 8, 12, 16)

    -- Diagonal rounds
    quarter_round(working_state, 1, 6, 11, 16)
    quarter_round(working_state, 2, 7, 12, 13)
    quarter_round(working_state, 3, 8, 9, 14)
    quarter_round(working_state, 4, 5, 10, 15)
  end

  -- Add original state to working state
  for i = 1, 16 do
    working_state[i] = bit32_raw_add(working_state[i], state[i])
  end

  local result_bytes = {}
  for i = 1, 16 do
    result_bytes[i] = bit32_u32_to_le_bytes(working_state[i])
  end

  return table_concat(result_bytes)
end

--- ChaCha20 encryption/decryption (same operation)
--- @param key string 32-byte key
--- @param nonce string 12-byte nonce
--- @param plaintext string Data to encrypt/decrypt
--- @param counter? integer Initial counter value (default: 1)
--- @return string ciphertext Encrypted/decrypted data
function chacha20.crypt(key, nonce, plaintext, counter)
  counter = counter or 1

  local result_bytes = {}
  local result_idx = 1
  local offset = 1
  local data_len = #plaintext

  while offset <= data_len do
    -- Generate keystream block
    local keystream = chacha20_block(key, nonce, counter)

    -- XOR with plaintext (optimized with local references)
    local block_size = min(64, data_len - offset + 1)
    for i = 1, block_size do
      local plaintext_byte = string_byte(plaintext, offset + i - 1)
      local keystream_byte = string_byte(keystream, i)
      result_bytes[result_idx] = string_char(bit32_raw_bxor(plaintext_byte, keystream_byte))
      result_idx = result_idx + 1
    end

    offset = offset + 64
    counter = counter + 1
  end

  return table_concat(result_bytes)
end

--- Convenience function for encryption (same as crypt)
--- @param key string 32-byte key
--- @param nonce string 12-byte nonce
--- @param plaintext string Data to encrypt
--- @param counter? integer Initial counter value (default: 1)
--- @return string ciphertext Encrypted data
function chacha20.encrypt(key, nonce, plaintext, counter)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl and #plaintext > 0 then
    -- Prepend 32-bit counter to 96-bit nonce for complete 128-bit nonce
    nonce = bytes.u32_to_le_bytes(counter or 1) .. nonce
    return openssl.cipher.encrypt("chacha20", plaintext, key, nonce)
  end
  return chacha20.crypt(key, nonce, plaintext, counter)
end

--- Convenience function for decryption (same as crypt)
--- @param key string 32-byte key
--- @param nonce string 12-byte nonce
--- @param ciphertext string Data to decrypt
--- @param counter? integer Initial counter value (default: 1)
--- @return string plaintext Decrypted data
function chacha20.decrypt(key, nonce, ciphertext, counter)
  -- Check if we should use OpenSSL
  local openssl = openssl_wrapper.get()
  if openssl and #ciphertext > 0 then
    -- Prepend 32-bit counter to 96-bit nonce for complete 128-bit nonce
    nonce = bytes.u32_to_le_bytes(counter or 1) .. nonce
    return openssl.cipher.decrypt("chacha20", ciphertext, key, nonce)
  end
  return chacha20.crypt(key, nonce, ciphertext, counter)
end

-- Private functions and values the tests in test/ check directly.
chacha20._internal = {
  chacha20_block = chacha20_block,
}

return chacha20
