--- @module "crypto.aes_ccm"
--- AES-CCM authenticated encryption: Counter with CBC-MAC, RFC 3610 and NIST
--- SP 800-38C.
---
--- CCM authenticates with a CBC-MAC over a header block, the associated data
--- and the plaintext, then encrypts the plaintext and the tag in counter mode.
--- Both halves use only the forward AES block cipher, which comes from
--- `crypto.aes_core`.
---
--- Parameters, all checked on every call:
---
--- * key: 16, 24 or 32 bytes (AES-128/192/256)
--- * nonce: 7 to 13 bytes. The length field takes the rest of the 15 bytes, so a
---   13-byte nonce caps the message at 65535 bytes and a 7-byte one leaves it
---   effectively unbounded.
--- * tag_length: an even number from 4 to 16, default 16
---
--- OpenSSL acceleration
--- --------------------
--- lua-openssl's own `aes-128-ccm` cannot be used on the binding Control4 ships
--- (0.8.5, measured 2026-11-03): it has no way to set the message length, and
--- without associated data it returns no tag. So the mode is built here over a
--- single-block AES call. With `crypto.use_openssl(true)` and a binding that
--- passes `Feature.ECB`, each block goes through `cipher:encrypt(..., false)`,
--- and the whole counter-mode keystream is one call. The CBC-MAC is a chain, so
--- it stays one call per block.
---
--- @usage
--- local aes_ccm = require("crypto.aes_ccm")
--- local sealed = aes_ccm.encrypt(key, nonce, plaintext, aad) -- ciphertext .. 16-byte tag
--- local opened = aes_ccm.decrypt(key, nonce, sealed, aad) -- plaintext, or nil
---
--- @class crypto.aes_ccm
local aes_ccm = {}

local bit32 = require("bitn").bit32

local aes_core = require("crypto.aes_core")
local utils = require("crypto.utils")
local bytes = utils.bytes

-- Local references for performance
local bit32_raw_bxor = bit32.raw_bxor
local ceil = math.ceil
local floor = math.floor
local string_byte = string.byte
local string_char = string.char
local string_rep = string.rep
local string_sub = string.sub
local table_concat = table.concat

-- ============================================================================
-- INTERNAL HELPERS
-- ============================================================================

--- Check the parameters every call shares.
--- @param key string AES key
--- @param nonce string Nonce
--- @param tag_length integer? Tag length in bytes
--- @return integer L Bytes of the length field (15 - #nonce)
--- @return integer tag_length Tag length with the default applied
local function check_parameters(key, nonce, tag_length)
  assert(type(key) == "string" and (#key == 16 or #key == 24 or #key == 32), "AES-CCM: key must be 16, 24, or 32 bytes")
  assert(type(nonce) == "string" and #nonce >= 7 and #nonce <= 13, "AES-CCM: nonce must be 7 to 13 bytes")
  tag_length = tag_length or 16
  assert(
    type(tag_length) == "number" and tag_length >= 4 and tag_length <= 16 and tag_length % 2 == 0,
    "AES-CCM: tag length must be an even number of bytes from 4 to 16"
  )
  return 15 - #nonce, tag_length
end

--- Refuse a message too long for the length field.
--- @param length integer Message length in bytes
--- @param L integer Bytes of the length field
local function check_message_length(length, L)
  -- From L = 7 the field holds more than any Lua string can.
  if L < 7 and length >= 256 ^ L then
    error("AES-CCM: a " .. (15 - L) .. "-byte nonce limits the message to " .. (floor(256 ^ L) - 1) .. " bytes", 3)
  end
end

--- Big-endian encoding of a non-negative integer in a fixed width.
--- @param n integer Value
--- @param width integer Bytes
--- @return string encoded
local function be_bytes(n, width)
  local out = {}
  for i = width, 1, -1 do
    out[i] = string_char(n % 256)
    n = floor(n / 256)
  end
  return table_concat(out)
end

--- XOR `a` with the first #a bytes of `b`.
--- @param a string
--- @param b string At least as long as `a`
--- @return string result
local function xor_prefix(a, b)
  local out = {}
  for i = 1, #a do
    out[i] = string_char(bit32_raw_bxor(string_byte(a, i), string_byte(b, i)))
  end
  return table_concat(out)
end

--- Zero-pad to a whole number of 16-byte blocks ("" stays "").
--- @param data string
--- @return string padded
local function pad_block(data)
  local remainder = #data % 16
  if remainder == 0 then
    return data
  end
  return data .. string_rep("\0", 16 - remainder)
end

--- The associated-data length prefix of RFC 3610 section 2.2.
--- @param length integer Associated data length in bytes, > 0
--- @return string encoded
local function encode_aad_length(length)
  if length < 0xFF00 then
    return be_bytes(length, 2)
  elseif length < 2 ^ 32 then
    return "\255\254" .. be_bytes(length, 4)
  end
  return "\255\255" .. be_bytes(length, 8)
end

--- CBC-MAC over B_0, the encoded associated data and the message, truncated.
--- @param encrypt fun(blocks: string): string ECB encryptor for the key
--- @param nonce string Nonce
--- @param L integer Bytes of the length field
--- @param tag_length integer Tag length in bytes
--- @param aad string Associated data
--- @param message string Plaintext
--- @return string tag Unencrypted tag T
local function cbc_mac(encrypt, nonce, L, tag_length, aad, message)
  -- Flags: Adata in bit 6, (M - 2) / 2 in bits 3-5, L - 1 in bits 0-2.
  local flags = (#aad > 0 and 64 or 0) + 4 * (tag_length - 2) + (L - 1)
  local x = encrypt(string_char(flags) .. nonce .. be_bytes(#message, L))
  local function absorb(data)
    for i = 1, #data, 16 do
      x = encrypt(xor_prefix(x, string_sub(data, i, i + 15)))
    end
  end
  if #aad > 0 then
    absorb(pad_block(encode_aad_length(#aad) .. aad))
  end
  absorb(pad_block(message))
  return string_sub(x, 1, tag_length)
end

--- Counter-mode keystream blocks S_0, S_1, ... in one batch.
---
--- S_0 encrypts the tag and S_1 onward the message, so `blocks` is one more
--- than the message's block count.
--- @param encrypt fun(blocks: string): string ECB encryptor for the key
--- @param nonce string Nonce
--- @param L integer Bytes of the length field
--- @param blocks integer Counter blocks to produce, starting at 0
--- @return string keystream 16 * blocks bytes
local function keystream(encrypt, nonce, L, blocks)
  local prefix = string_char(L - 1) .. nonce
  local counters = {}
  for i = 0, blocks - 1 do
    counters[i + 1] = prefix .. be_bytes(i, L)
  end
  return encrypt(table_concat(counters))
end

-- ============================================================================
-- AEAD INTERFACE
-- ============================================================================

--- AES-CCM encryption.
---
--- @param key string AES key (16, 24, or 32 bytes)
--- @param nonce string 7 to 13 bytes, unique per message under one key
--- @param plaintext string Data to encrypt
--- @param aad? string Associated data, authenticated but not encrypted (default "")
--- @param tag_length? integer Tag bytes, even, 4 to 16 (default 16)
--- @return string sealed Ciphertext concatenated with the tag
function aes_ccm.encrypt(key, nonce, plaintext, aad, tag_length)
  local L
  L, tag_length = check_parameters(key, nonce, tag_length)
  assert(type(plaintext) == "string", "AES-CCM: plaintext must be a string")
  aad = aad or ""
  assert(type(aad) == "string", "AES-CCM: aad must be a string")
  check_message_length(#plaintext, L)

  local encrypt = aes_core.ecb_encryptor(key)
  local tag = cbc_mac(encrypt, nonce, L, tag_length, aad, plaintext)
  local stream = keystream(encrypt, nonce, L, ceil(#plaintext / 16) + 1)
  return xor_prefix(plaintext, string_sub(stream, 17)) .. xor_prefix(tag, stream)
end

--- AES-CCM decryption.
---
--- The tag is compared in constant time, and no plaintext is returned unless it
--- matches.
---
--- @param key string AES key (16, 24, or 32 bytes)
--- @param nonce string The nonce used to encrypt
--- @param ciphertext_and_tag string Output of `encrypt`
--- @param aad? string Associated data (default "")
--- @param tag_length? integer Tag bytes, even, 4 to 16 (default 16)
--- @return string? plaintext Decrypted data, or nil if authentication fails
function aes_ccm.decrypt(key, nonce, ciphertext_and_tag, aad, tag_length)
  local L
  L, tag_length = check_parameters(key, nonce, tag_length)
  assert(
    type(ciphertext_and_tag) == "string" and #ciphertext_and_tag >= tag_length,
    "AES-CCM: input must hold at least the " .. tag_length .. "-byte tag"
  )
  aad = aad or ""
  assert(type(aad) == "string", "AES-CCM: aad must be a string")
  local ciphertext_length = #ciphertext_and_tag - tag_length
  check_message_length(ciphertext_length, L)

  local ciphertext = string_sub(ciphertext_and_tag, 1, ciphertext_length)
  local received_tag = string_sub(ciphertext_and_tag, ciphertext_length + 1)

  local encrypt = aes_core.ecb_encryptor(key)
  local stream = keystream(encrypt, nonce, L, ceil(ciphertext_length / 16) + 1)
  local plaintext = xor_prefix(ciphertext, string_sub(stream, 17))
  local expected_tag = xor_prefix(cbc_mac(encrypt, nonce, L, tag_length, aad, plaintext), stream)
  if not bytes.constant_time_compare(expected_tag, received_tag) then
    return nil
  end
  return plaintext
end

return aes_ccm
