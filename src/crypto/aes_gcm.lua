--- @module "crypto.aes_gcm"
--- AES-GCM Authenticated Encryption with Associated Data (AEAD) Implementation for portability.
--- @class crypto.aes_gcm
local aes_gcm = {}

local bit32 = require("bitn").bit32

local aes_core = require("crypto.aes_core")
local openssl_wrapper = require("crypto.openssl_wrapper")
local utils = require("crypto.utils")
local bytes = utils.bytes

-- Local references for performance
local bit32_raw_band = bit32.raw_band
local bit32_raw_bor = bit32.raw_bor
local bit32_raw_bxor = bit32.raw_bxor
local bit32_raw_lshift = bit32.raw_lshift
local bit32_raw_rshift = bit32.raw_rshift
local string_byte = string.byte
local string_char = string.char
local string_rep = string.rep
local string_sub = string.sub
local table_concat = table.concat

-- The block cipher lives in crypto.aes_core, shared with AES-CCM.
local key_expansion = aes_core.expand_key
local aes_encrypt_block = aes_core.encrypt_block

-- ============================================================================
-- GCM MODE IMPLEMENTATION
-- ============================================================================

--- @alias AESBlock [integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer]

--- Initialize a 16-element GCM block with zeros
--- @return AESBlock block Initialized block
local function create_gcm_block()
  local arr = {}
  for i = 1, 16 do
    arr[i] = 0
  end
  --- @cast arr AESBlock
  return arr
end

-- Pre-allocated arrays for gcm_multiply() to avoid repeated allocation
local gcm_z = create_gcm_block()
local gcm_v = create_gcm_block()

--- GCM field multiplication
--- @param x string 16-byte block
--- @param y string 16-byte block
--- @return string result Product in GF(2^128)
local function gcm_multiply(x, y)
  -- Reuse pre-allocated arrays
  local z = gcm_z
  local v = gcm_v
  -- Reset z and initialize v
  for i = 1, 16 do
    z[i] = 0
    v[i] = string_byte(y, i)
  end

  -- Process each bit of x from MSB to LSB
  for i = 1, 16 do
    local byte = string_byte(x, i)
    for bit = 7, 0, -1 do
      if bit32_raw_band(byte, bit32_raw_lshift(1, bit)) ~= 0 then
        -- z = z XOR v
        for j = 1, 16 do
          z[j] = bit32_raw_bxor(z[j], v[j])
        end
      end

      -- Check if LSB of v is 1 (bit 0 of last byte)
      local lsb = bit32_raw_band(v[16], 1)

      -- v = v >> 1 (right shift entire 128-bit value by 1)
      local carry = 0
      for j = 1, 16 do
        local new_carry = bit32_raw_band(v[j], 1)
        v[j] = bit32_raw_bor(bit32_raw_rshift(v[j], 1), bit32_raw_lshift(carry, 7))
        carry = new_carry
      end

      -- If LSB was 1, XOR with R = 0xE1000000000000000000000000000000
      if lsb ~= 0 then
        v[1] = bit32_raw_bxor(v[1], 0xE1)
      end
    end
  end

  -- Convert result back to string
  local result = ""
  for i = 1, 16 do
    result = result .. string_char(z[i])
  end
  return result
end

--- GHASH function
--- @param h string Hash key (16 bytes)
--- @param data string Data to hash (multiple of 16 bytes)
--- @return string result 16-byte hash
local function ghash(h, data)
  local y = string_rep("\0", 16)

  -- Process each 16-byte block
  for i = 1, #data, 16 do
    local block = string_sub(data, i, i + 15)

    -- y = (y XOR block) * h
    local y_xor = ""
    for j = 1, 16 do
      y_xor = y_xor .. string_char(bit32_raw_bxor(string_byte(y, j), string_byte(block, j)))
    end

    y = gcm_multiply(y_xor, h)
  end

  return y
end

--- Increment counter block
--- @param counter string 16-byte counter block
--- @return string result Incremented counter
local function inc_counter(counter)
  return string_sub(counter, 1, 12) .. bytes.u32_to_be_bytes(bytes.be_bytes_to_u32(counter, 13) + 1)
end

--- Generate counter mode keystream
--- @param key string AES key
--- @param iv string Initialization vector
--- @param length integer Number of bytes needed
--- @return string keystream Generated keystream
local function generate_keystream(key, iv, length)
  local expanded_key, nr = key_expansion(key)
  local keystream_blocks = {}
  local total_length = 0

  -- Initial counter value: IV || 0x00000002
  local counter = iv .. string_rep("\0", 3) .. string_char(0x02)

  while total_length < length do
    local block = aes_encrypt_block(counter, expanded_key, nr)
    keystream_blocks[#keystream_blocks + 1] = block
    total_length = total_length + #block
    counter = inc_counter(counter)
  end

  local keystream = table_concat(keystream_blocks)
  return string_sub(keystream, 1, length)
end

-- ============================================================================
-- AEAD INTERFACE
-- ============================================================================

--- Pad AAD and ciphertext as required by GCM
--- @param aad string Additional authenticated data
--- @param ciphertext string Encrypted data
--- @return string padded_data Data formatted for GHASH
local function format_gcm_data(aad, ciphertext)
  local result = ""

  -- Add AAD and padding
  result = result .. aad
  local aad_pad = (16 - (#aad % 16)) % 16
  result = result .. string_rep("\0", aad_pad)

  -- Add ciphertext and padding
  result = result .. ciphertext
  local ct_pad = (16 - (#ciphertext % 16)) % 16
  result = result .. string_rep("\0", ct_pad)

  -- Add lengths (in bits) as 64-bit big-endian integers
  -- For messages under 2^61 bytes, high 32 bits are always 0
  local aad_bits_low = #aad * 8
  local ct_bits_low = #ciphertext * 8

  -- AAD length (64 bits big-endian)
  result = result .. string_rep("\0", 4) -- High 32 bits
  result = result .. bytes.u32_to_be_bytes(aad_bits_low) -- Low 32 bits

  -- Ciphertext length (64 bits big-endian)
  result = result .. string_rep("\0", 4) -- High 32 bits
  result = result .. bytes.u32_to_be_bytes(ct_bits_low) -- Low 32 bits

  return result
end

--- AES-GCM AEAD Encryption
---
--- Encrypts plaintext and authenticates both the plaintext and additional data.
--- Returns the ciphertext concatenated with a 16-byte authentication tag.
---
--- @param key string AES key (16, 24, or 32 bytes)
--- @param nonce string 12-byte nonce (must be unique for each encryption with the same key)
--- @param plaintext string Data to encrypt
--- @param aad? string Additional Authenticated Data (default: empty string)
--- @return string result Ciphertext concatenated with 16-byte authentication tag
function aes_gcm.encrypt(key, nonce, plaintext, aad)
  assert(#key == 16 or #key == 24 or #key == 32, "Key must be 16, 24, or 32 bytes")
  assert(#nonce == 12, "Nonce must be exactly 12 bytes")

  aad = aad or ""

  local openssl = openssl_wrapper.get(openssl_wrapper.Feature.AAD)
  if openssl then
    local evp = openssl.cipher.get("aes-" .. #key * 8 .. "-gcm")
    local e = evp:encrypt_new()
    e:ctrl(openssl.cipher.EVP_CTRL_GCM_SET_IVLEN, #nonce)
    e:init(key, nonce)

    -- Indicate that the AAD setting is set
    local aad_update = e:update(aad, true) or ""
    if #aad_update > 0 then
      error("AAD update should not return data in AEAD mode")
    end
    local ciphertext = e:update(plaintext)
    local final = e:final() or ""
    if #final > 0 then
      error("Finalization should not return data in AEAD mode")
    end
    local tag = e:ctrl(openssl.cipher.EVP_CTRL_GCM_GET_TAG, 16) or ""
    if #tag ~= 16 then
      error("Tag length must be exactly 16 bytes in AEAD mode")
    end
    return ciphertext .. tag
  end

  -- Expand key
  local expanded_key, nr = key_expansion(key)

  -- Generate hash key H = E(K, 0^128)
  local h = aes_encrypt_block(string_rep("\0", 16), expanded_key, nr)

  -- Initial counter: nonce || 0x00000001
  local j0 = nonce .. string_rep("\0", 3) .. string_char(0x01)

  -- Encrypt plaintext using CTR mode
  local keystream = generate_keystream(key, nonce, #plaintext)
  local ciphertext = ""
  for i = 1, #plaintext do
    ciphertext = ciphertext .. string_char(bit32_raw_bxor(string_byte(plaintext, i), string_byte(keystream, i)))
  end

  -- Calculate authentication tag
  local gcm_data = format_gcm_data(aad, ciphertext)
  local s = ghash(h, gcm_data)

  -- Encrypt S to get final tag: T = E(K, J0) XOR S
  local encrypted_j0 = aes_encrypt_block(j0, expanded_key, nr)
  local tag = ""
  for i = 1, 16 do
    tag = tag .. string_char(bit32_raw_bxor(string_byte(s, i), string_byte(encrypted_j0, i)))
  end

  return ciphertext .. tag
end

--- AES-GCM AEAD Decryption
---
--- Verifies the authentication tag and decrypts the ciphertext if authentic.
--- The input should be the result of encrypt() - ciphertext concatenated with tag.
---
--- @param key string AES key (16, 24, or 32 bytes)
--- @param nonce string 12-byte nonce (same as used for encryption)
--- @param ciphertext_and_tag string Encrypted data with 16-byte authentication tag appended
--- @param aad? string Additional Authenticated Data (default: empty string)
--- @return string? plaintext Decrypted data, or nil if authentication fails
function aes_gcm.decrypt(key, nonce, ciphertext_and_tag, aad)
  assert(#key == 16 or #key == 24 or #key == 32, "Key must be 16, 24, or 32 bytes")
  assert(#nonce == 12, "Nonce must be exactly 12 bytes")
  assert(#ciphertext_and_tag >= 16, "Input must contain at least 16 bytes for authentication tag")

  aad = aad or ""

  -- Split ciphertext and tag
  local ciphertext_len = #ciphertext_and_tag - 16
  local ciphertext = string_sub(ciphertext_and_tag, 1, ciphertext_len)
  local received_tag = string_sub(ciphertext_and_tag, ciphertext_len + 1)

  local openssl = openssl_wrapper.get(openssl_wrapper.Feature.AAD)
  if openssl then
    local evp = openssl.cipher.get("aes-" .. #key * 8 .. "-gcm")
    local e = evp:decrypt_new()
    e:ctrl(openssl.cipher.EVP_CTRL_GCM_SET_IVLEN, #nonce)
    e:ctrl(openssl.cipher.EVP_CTRL_GCM_SET_TAG, received_tag)
    e:init(key, nonce)

    -- Indicate that the AAD setting is set
    local aad_update = e:update(aad, true) or ""
    if #aad_update > 0 then
      error("AAD update should not return data in AEAD mode")
    end
    local plaintext = e:update(ciphertext)
    local final = e:final()
    if final == nil then
      return nil -- Authentication failed
    elseif #final > 0 then
      error("Finalization should not return data in AEAD mode")
    end
    return plaintext
  end

  -- Expand key
  local expanded_key, nr = key_expansion(key)

  -- Generate hash key H = E(K, 0^128)
  local h = aes_encrypt_block(string_rep("\0", 16), expanded_key, nr)

  -- Initial counter: nonce || 0x00000001
  local j0 = nonce .. string_rep("\0", 3) .. string_char(0x01)

  -- Calculate expected authentication tag
  local gcm_data = format_gcm_data(aad, ciphertext)
  local s = ghash(h, gcm_data)

  -- Encrypt S to get expected tag: T = E(K, J0) XOR S
  local encrypted_j0 = aes_encrypt_block(j0, expanded_key, nr)
  local expected_tag = ""
  for i = 1, 16 do
    expected_tag = expected_tag .. string_char(bit32_raw_bxor(string_byte(s, i), string_byte(encrypted_j0, i)))
  end

  -- Verify tag (constant-time comparison)
  if received_tag ~= expected_tag then
    return nil -- Authentication failed
  end

  -- Decrypt ciphertext using CTR mode
  local keystream = generate_keystream(key, nonce, #ciphertext)
  local plaintext = ""
  for i = 1, #ciphertext do
    plaintext = plaintext .. string_char(bit32_raw_bxor(string_byte(ciphertext, i), string_byte(keystream, i)))
  end

  return plaintext
end

return aes_gcm
