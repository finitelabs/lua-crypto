--- @module "crypto.chacha20_poly1305"
--- ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) Implementation for portability.
--- @class crypto.chacha20_poly1305
local chacha20_poly1305 = {}

local openssl_wrapper = require("crypto.openssl_wrapper")
local utils = require("crypto.utils")
local bytes = utils.bytes
local chacha20 = require("crypto.chacha20")
local poly1305 = require("crypto.poly1305")

local string_rep = string.rep
local string_sub = string.sub
local table_concat = table.concat

--- Generate Poly1305 one-time key using ChaCha20
--- @param key string 32-byte ChaCha20 key
--- @param nonce string 12-byte nonce
--- @return string poly_key 32-byte Poly1305 one-time key
local function poly1305_key_gen(key, nonce)
  -- Generate Poly1305 key by encrypting 32 zero bytes with ChaCha20
  -- Counter starts at 0 for key generation
  local zero_block = string_rep("\0", 32)
  return chacha20.crypt(key, nonce, zero_block, 0)
end

--- Construct authentication data for Poly1305
--- @param aad string Additional Authenticated Data
--- @param ciphertext string Encrypted data
--- @return string auth_data Data to be authenticated
local function construct_aad_data(aad, ciphertext)
  local aad_len = #aad
  local ciphertext_len = #ciphertext

  -- Construct the data to authenticate according to RFC 8439:
  -- AAD || pad16(AAD) || ciphertext || pad16(ciphertext) || num_to_8_le_bytes(aad_len) || num_to_8_le_bytes(ciphertext_len)
  local auth_parts = {
    bytes.pad_to_16(aad),
    bytes.pad_to_16(ciphertext),
    bytes.u64_to_le_bytes(aad_len),
    bytes.u64_to_le_bytes(ciphertext_len),
  }

  return table_concat(auth_parts)
end

-- ============================================================================
-- CHACHA20-POLY1305 AEAD PUBLIC INTERFACE
-- ============================================================================

--- ChaCha20-Poly1305 AEAD Encryption
---
--- Encrypts plaintext and authenticates both the plaintext and additional data.
--- Returns the ciphertext concatenated with a 16-byte authentication tag.
---
--- @param key string 32-byte encryption key
--- @param nonce string 12-byte nonce (must be unique for each encryption with the same key)
--- @param plaintext string Data to encrypt
--- @param aad? string Additional Authenticated Data (default: empty string)
--- @return string result Ciphertext concatenated with 16-byte authentication tag
function chacha20_poly1305.encrypt(key, nonce, plaintext, aad)
  assert(#key == 32, "Key must be exactly 32 bytes")
  assert(#nonce == 12, "Nonce must be exactly 12 bytes")

  aad = aad or ""

  local openssl = openssl_wrapper.get(openssl_wrapper.Feature.AAD)
  if openssl then
    local evp = openssl.cipher.get("chacha20-poly1305")
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

  -- Step 1: Generate Poly1305 one-time key
  local poly_key = poly1305_key_gen(key, nonce)

  -- Step 2: Encrypt plaintext with ChaCha20
  local ciphertext = chacha20.crypt(key, nonce, plaintext)

  -- Step 3: Construct authentication data
  local auth_data = construct_aad_data(aad, ciphertext)

  -- Step 4: Generate authentication tag with Poly1305
  local tag = poly1305.authenticate(poly_key, auth_data)

  -- Step 5: Return ciphertext || tag
  return ciphertext .. tag
end

--- ChaCha20-Poly1305 AEAD Decryption
---
--- Verifies the authentication tag and decrypts the ciphertext if authentic.
--- The input should be the result of encrypt() - ciphertext concatenated with tag.
---
--- @param key string 32-byte encryption key
--- @param nonce string 12-byte nonce (same as used for encryption)
--- @param ciphertext_and_tag string Encrypted data with 16-byte authentication tag appended
--- @param aad? string Additional Authenticated Data (default: empty string)
--- @return string? plaintext Decrypted data, or nil if authentication fails
function chacha20_poly1305.decrypt(key, nonce, ciphertext_and_tag, aad)
  assert(#key == 32, "Key must be exactly 32 bytes")
  assert(#nonce == 12, "Nonce must be exactly 12 bytes")
  assert(#ciphertext_and_tag >= 16, "Input must contain at least 16 bytes for authentication tag")

  aad = aad or ""

  -- Step 1: Split ciphertext and tag
  local ciphertext_len = #ciphertext_and_tag - 16
  local ciphertext = string_sub(ciphertext_and_tag, 1, ciphertext_len)
  local received_tag = string_sub(ciphertext_and_tag, ciphertext_len + 1)

  local openssl = openssl_wrapper.get(openssl_wrapper.Feature.AAD)
  if openssl then
    local evp = openssl.cipher.get("chacha20-poly1305")
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

  -- Step 2: Generate Poly1305 one-time key (same as encryption)
  local poly_key = poly1305_key_gen(key, nonce)

  -- Step 3: Construct authentication data (same as encryption)
  local auth_data = construct_aad_data(aad, ciphertext)

  -- Step 4: Compute expected authentication tag
  local expected_tag = poly1305.authenticate(poly_key, auth_data)

  -- Step 5: Verify authentication tag (constant-time comparison)
  if received_tag ~= expected_tag then
    return nil -- Authentication failed
  end

  -- Step 6: Decrypt ciphertext with ChaCha20 (counter starts at 1)
  local plaintext = chacha20.crypt(key, nonce, ciphertext, 1)

  return plaintext
end

-- Private functions the tests in test/ check directly.
chacha20_poly1305._internal = {
  poly1305_key_gen = poly1305_key_gen,
}

return chacha20_poly1305
