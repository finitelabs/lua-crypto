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
local openssl_wrapper = require("crypto.openssl_wrapper")
local utils = require("crypto.utils")
local bytes = utils.bytes
local benchmark_op = utils.benchmark.benchmark_op

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

-- ============================================================================
-- TEST VECTORS AND VALIDATION
-- ============================================================================

--- FIPS-197 Appendix C: one block under each key size, as hex.
local FIPS197_PLAINTEXT = "00112233445566778899aabbccddeeff"
local FIPS197_VECTORS = {
  { name = "C.1 AES-128", key = "000102030405060708090a0b0c0d0e0f", ciphertext = "69c4e0d86a7b0430d8cdb78070b4c55a" },
  {
    name = "C.2 AES-192",
    key = "000102030405060708090a0b0c0d0e0f1011121314151617",
    ciphertext = "dda97ca4864cdfe06eaf70a0ec0d7191",
  },
  {
    name = "C.3 AES-256",
    key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ciphertext = "8ea2b7ca516745bfeafc49904b496089",
  },
}

--- Known answers as hex. `sealed` is ciphertext .. tag.
---
--- * RFC 3610 section 8, packet vectors #1-#24 (AES-128, 13-byte nonce), copied
---   from the RFC text: the packet's leading cleartext octets are `aad`.
--- * NIST SP 800-38C Appendix C, examples 1-4. Example 4's associated data is
---   65536 bytes, i mod 256, so it is built at run time and exercises the
---   0xFFFE length prefix.
--- * Four cases the published sets do not reach (AES-192/256, a 7-byte nonce, no
---   associated data, an empty plaintext), generated with pyca/cryptography's
---   AESCCM, an OpenSSL-backed implementation that reproduces every vector above.
local test_vectors = {
  {
    name = "RFC 3610 packet vector #1",
    key = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    nonce = "00000003020100a0a1a2a3a4a5",
    aad = "0001020304050607",
    plaintext = "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
    sealed = "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0",
    tag_length = 8,
  },
  {
    name = "RFC 3610 packet vector #2",
    key = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    nonce = "00000004030201a0a1a2a3a4a5",
    aad = "0001020304050607",
    plaintext = "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    sealed = "72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3ba091d56e10400916",
    tag_length = 8,
  },
  {
    name = "RFC 3610 packet vector #3",
    key = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    nonce = "00000005040302a0a1a2a3a4a5",
    aad = "0001020304050607",
    plaintext = "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    sealed = "51b1e5f44a197d1da46b0f8e2d282ae871e838bb64da8596574adaa76fbd9fb0c5",
    tag_length = 8,
  },
  {
    name = "RFC 3610 packet vector #4",
    key = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    nonce = "00000006050403a0a1a2a3a4a5",
    aad = "000102030405060708090a0b",
    plaintext = "0c0d0e0f101112131415161718191a1b1c1d1e",
    sealed = "a28c6865939a9a79faaa5c4c2a9d4a91cdac8c96c861b9c9e61ef1",
    tag_length = 8,
  },
  {
    name = "RFC 3610 packet vector #5",
    key = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    nonce = "00000007060504a0a1a2a3a4a5",
    aad = "000102030405060708090a0b",
    plaintext = "0c0d0e0f101112131415161718191a1b1c1d1e1f",
    sealed = "dcf1fb7b5d9e23fb9d4e131253658ad86ebdca3e51e83f077d9c2d93",
    tag_length = 8,
  },
  {
    name = "RFC 3610 packet vector #6",
    key = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    nonce = "00000008070605a0a1a2a3a4a5",
    aad = "000102030405060708090a0b",
    plaintext = "0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    sealed = "6fc1b011f006568b5171a42d953d469b2570a4bd87405a0443ac91cb94",
    tag_length = 8,
  },
  {
    name = "RFC 3610 packet vector #7",
    key = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    nonce = "00000009080706a0a1a2a3a4a5",
    aad = "0001020304050607",
    plaintext = "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
    sealed = "0135d1b2c95f41d5d1d4fec185d166b8094e999dfed96c048c56602c97acbb7490",
    tag_length = 10,
  },
  {
    name = "RFC 3610 packet vector #8",
    key = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    nonce = "0000000a090807a0a1a2a3a4a5",
    aad = "0001020304050607",
    plaintext = "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    sealed = "7b75399ac0831dd2f0bbd75879a2fd8f6cae6b6cd9b7db24c17b4433f434963f34b4",
    tag_length = 10,
  },
  {
    name = "RFC 3610 packet vector #9",
    key = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    nonce = "0000000b0a0908a0a1a2a3a4a5",
    aad = "0001020304050607",
    plaintext = "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    sealed = "82531a60cc24945a4b8279181ab5c84df21ce7f9b73f42e197ea9c07e56b5eb17e5f4e",
    tag_length = 10,
  },
  {
    name = "RFC 3610 packet vector #10",
    key = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    nonce = "0000000c0b0a09a0a1a2a3a4a5",
    aad = "000102030405060708090a0b",
    plaintext = "0c0d0e0f101112131415161718191a1b1c1d1e",
    sealed = "07342594157785152b074098330abb141b947b566aa9406b4d999988dd",
    tag_length = 10,
  },
  {
    name = "RFC 3610 packet vector #11",
    key = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    nonce = "0000000d0c0b0aa0a1a2a3a4a5",
    aad = "000102030405060708090a0b",
    plaintext = "0c0d0e0f101112131415161718191a1b1c1d1e1f",
    sealed = "676bb20380b0e301e8ab79590a396da78b834934f53aa2e9107a8b6c022c",
    tag_length = 10,
  },
  {
    name = "RFC 3610 packet vector #12",
    key = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    nonce = "0000000e0d0c0ba0a1a2a3a4a5",
    aad = "000102030405060708090a0b",
    plaintext = "0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    sealed = "c0ffa0d6f05bdb67f24d43a4338d2aa4bed7b20e43cd1aa31662e7ad65d6db",
    tag_length = 10,
  },
  {
    name = "RFC 3610 packet vector #13",
    key = "d7828d13b2b0bdc325a76236df93cc6b",
    nonce = "00412b4ea9cdbe3c9696766cfa",
    aad = "0be1a88bace018b1",
    plaintext = "08e8cf97d820ea258460e96ad9cf5289054d895ceac47c",
    sealed = "4cb97f86a2a4689a877947ab8091ef5386a6ffbdd080f8e78cf7cb0cddd7b3",
    tag_length = 8,
  },
  {
    name = "RFC 3610 packet vector #14",
    key = "d7828d13b2b0bdc325a76236df93cc6b",
    nonce = "0033568ef7b2633c9696766cfa",
    aad = "63018f76dc8a1bcb",
    plaintext = "9020ea6f91bdd85afa0039ba4baff9bfb79c7028949cd0ec",
    sealed = "4ccb1e7ca981befaa0726c55d378061298c85c92814abc33c52ee81d7d77c08a",
    tag_length = 8,
  },
  {
    name = "RFC 3610 packet vector #15",
    key = "d7828d13b2b0bdc325a76236df93cc6b",
    nonce = "00103fe41336713c9696766cfa",
    aad = "aa6cfa36cae86b40",
    plaintext = "b916e0eacc1c00d7dcec68ec0b3bbb1a02de8a2d1aa346132e",
    sealed = "b1d23a2220ddc0ac900d9aa03c61fcf4a559a4417767089708a776796edb723506",
    tag_length = 8,
  },
  {
    name = "RFC 3610 packet vector #16",
    key = "d7828d13b2b0bdc325a76236df93cc6b",
    nonce = "00764c63b8058e3c9696766cfa",
    aad = "d0d0735c531e1becf049c244",
    plaintext = "12daac5630efa5396f770ce1a66b21f7b2101c",
    sealed = "14d253c3967b70609b7cbb7c499160283245269a6f49975bcadeaf",
    tag_length = 8,
  },
  {
    name = "RFC 3610 packet vector #17",
    key = "d7828d13b2b0bdc325a76236df93cc6b",
    nonce = "00f8b678094e3b3c9696766cfa",
    aad = "77b60f011c03e1525899bcae",
    plaintext = "e88b6a46c78d63e52eb8c546efb5de6f75e9cc0d",
    sealed = "5545ff1a085ee2efbf52b2e04bee1e2336c73e3f762c0c7744fe7e3c",
    tag_length = 8,
  },
  {
    name = "RFC 3610 packet vector #18",
    key = "d7828d13b2b0bdc325a76236df93cc6b",
    nonce = "00d560912d3f703c9696766cfa",
    aad = "cd9044d2b71fdb8120ea60c0",
    plaintext = "6435acbafb11a82e2f071d7ca4a5ebd93a803ba87f",
    sealed = "009769ecabdf48625594c59251e6035722675e04c847099e5ae0704551",
    tag_length = 8,
  },
  {
    name = "RFC 3610 packet vector #19",
    key = "d7828d13b2b0bdc325a76236df93cc6b",
    nonce = "0042fff8f1951c3c9696766cfa",
    aad = "d85bc7e69f944fb8",
    plaintext = "8a19b950bcf71a018e5e6701c91787659809d67dbedd18",
    sealed = "bc218daa947427b6db386a99ac1aef23ade0b52939cb6a637cf9bec2408897c6ba",
    tag_length = 10,
  },
  {
    name = "RFC 3610 packet vector #20",
    key = "d7828d13b2b0bdc325a76236df93cc6b",
    nonce = "00920f40e56cdc3c9696766cfa",
    aad = "74a0ebc9069f5b37",
    plaintext = "1761433c37c5a35fc1f39f406302eb907c6163be38c98437",
    sealed = "5810e6fd25874022e80361a478e3e9cf484ab04f447efff6f0a477cc2fc9bf548944",
    tag_length = 10,
  },
  {
    name = "RFC 3610 packet vector #21",
    key = "d7828d13b2b0bdc325a76236df93cc6b",
    nonce = "0027ca0c7120bc3c9696766cfa",
    aad = "44a3aa3aae6475ca",
    plaintext = "a434a8e58500c6e41530538862d686ea9e81301b5ae4226bfa",
    sealed = "f2beed7bc5098e83feb5b31608f8e29c38819a89c8e776f1544d4151a4ed3a8b87b9ce",
    tag_length = 10,
  },
  {
    name = "RFC 3610 packet vector #22",
    key = "d7828d13b2b0bdc325a76236df93cc6b",
    nonce = "005b8ccbcd9af83c9696766cfa",
    aad = "ec46bb63b02520c33c49fd70",
    plaintext = "b96b49e21d621741632875db7f6c9243d2d7c2",
    sealed = "31d750a09da3ed7fddd49a2032aabf17ec8ebf7d22c8088c666be5c197",
    tag_length = 10,
  },
  {
    name = "RFC 3610 packet vector #23",
    key = "d7828d13b2b0bdc325a76236df93cc6b",
    nonce = "003ebe94044b9a3c9696766cfa",
    aad = "47a65ac78b3d594227e85e71",
    plaintext = "e2fcfbb880442c731bf95167c8ffd7895e337076",
    sealed = "e882f1dbd38ce3eda7c23f04dd65071eb41342acdf7e00dccec7ae52987d",
    tag_length = 10,
  },
  {
    name = "RFC 3610 packet vector #24",
    key = "d7828d13b2b0bdc325a76236df93cc6b",
    nonce = "008d493b30ae8b3c9696766cfa",
    aad = "6e37a6ef546d955d34ab6059",
    plaintext = "abf21c0b02feb88f856df4a37381bce3cc128517d4",
    sealed = "f32905b88a641b04b9c9ffb58cc390900f3da12ab16dce9e82efa16da62059",
    tag_length = 10,
  },
  {
    name = "NIST SP 800-38C example 1",
    key = "404142434445464748494a4b4c4d4e4f",
    nonce = "10111213141516",
    aad = "0001020304050607",
    plaintext = "20212223",
    sealed = "7162015b4dac255d",
    tag_length = 4,
  },
  {
    name = "NIST SP 800-38C example 2",
    key = "404142434445464748494a4b4c4d4e4f",
    nonce = "1011121314151617",
    aad = "000102030405060708090a0b0c0d0e0f",
    plaintext = "202122232425262728292a2b2c2d2e2f",
    sealed = "d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd",
    tag_length = 6,
  },
  {
    name = "NIST SP 800-38C example 3",
    key = "404142434445464748494a4b4c4d4e4f",
    nonce = "101112131415161718191a1b",
    aad = "000102030405060708090a0b0c0d0e0f10111213",
    plaintext = "202122232425262728292a2b2c2d2e2f3031323334353637",
    sealed = "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951",
    tag_length = 8,
  },
  {
    name = "pyca: AES-256, 12-byte nonce, no AAD",
    key = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    nonce = "a0a1a2a3a4a5a6a7a8a9aaab",
    plaintext = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
    sealed = "d4a4942560b0ea50e662268ff70c7318ca51040907d93100b3d2e2462939cbed7c92284e629dd8a13fdec3a088d1dc688df12f296a032710",
    tag_length = 16,
  },
  {
    name = "pyca: AES-192, 7-byte nonce (8-byte length field)",
    key = "505152535455565758595a5b5c5d5e5f6061626364656667",
    nonce = "b0b1b2b3b4b5b6",
    aad = "000102030405060708090a0b0c0d0e0f10111213",
    plaintext = "606162636465666768696a6b6c6d6e6f70",
    sealed = "4e8a800833923c5de55517e3dad64f77e132e1cc3c070a8eac44a20874",
    tag_length = 12,
  },
  {
    name = "pyca: AES-128, empty plaintext",
    key = "101112131415161718191a1b1c1d1e1f",
    nonce = "c0c1c2c3c4c5c6c7c8c9cacb",
    aad = "303132333435363738393a3b3c3d3e3f40",
    plaintext = "",
    sealed = "14f3195b79a70b0f2fa70b43fc1173af",
    tag_length = 16,
  },
  {
    name = "pyca: AES-128, 53 bytes, no AAD, default tag",
    key = "101112131415161718191a1b1c1d1e1f",
    nonce = "c0c1c2c3c4c5c6c7c8c9cacb",
    plaintext = "00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c",
    sealed = "1d3052b68843e374dcdcd52230fdccf7e65fd913da984b70beb22b1e4cc1e02812c97f87e38e295b9dd88517e0660d09998fe3f38e1a0de623e395d65a5cb05d098ffdc12e",
  },
}

--- Run the self-test: FIPS-197 blocks, the RFC 3610 and SP 800-38C vectors,
--- parameter checks, tamper detection, and the OpenSSL routing against a
--- stand-in binding.
--- @return boolean result True if all tests pass, false otherwise
function aes_ccm.selftest()
  local passed = 0
  local total = 0

  --- Record one result; a function that raises counts as a failure.
  --- @param name string
  --- @param result boolean|fun(): boolean
  local function check(name, result)
    total = total + 1
    if type(result) == "function" then
      local ok, value = pcall(result)
      result = ok and value == true
    end
    if result == true then
      print("  ✅ PASS: " .. name)
      passed = passed + 1
    else
      print("  ❌ FAIL: " .. name)
    end
  end

  --- Whether `fn` raises.
  --- @param fn function
  --- @return boolean raised
  local function raises(fn, ...)
    return pcall(fn, ...) == false
  end

  print("Running AES block cipher known answers (FIPS-197 Appendix C)...")
  local fips_plaintext = bytes.from_hex(FIPS197_PLAINTEXT)
  for _, vector in ipairs(FIPS197_VECTORS) do
    local key = bytes.from_hex(vector.key)
    local expected = bytes.from_hex(vector.ciphertext)
    check("FIPS-197 " .. vector.name .. " (pure-Lua block)", function()
      local expanded, nr = aes_core.expand_key(key)
      return aes_core.encrypt_block(fips_plaintext, expanded, nr) == expected
    end)
    check("FIPS-197 " .. vector.name .. " (ECB encryptor, two blocks)", function()
      return aes_core.ecb_encryptor(key)(fips_plaintext .. fips_plaintext) == expected .. expected
    end)
  end

  print("\nRunning AES-CCM test vectors...")
  -- SP 800-38C example 4's 65536-byte associated data.
  local long_aad = {}
  for i = 0, 65535 do
    long_aad[i + 1] = string_char(i % 256)
  end
  local vectors = {}
  for i, vector in ipairs(test_vectors) do
    vectors[i] = vector
  end
  vectors[#vectors + 1] = {
    name = "NIST SP 800-38C example 4 (65536-byte AAD)",
    key = "404142434445464748494a4b4c4d4e4f",
    nonce = "101112131415161718191a1b1c",
    aad_bytes = table_concat(long_aad),
    plaintext = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    sealed = "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b",
    tag_length = 14,
  }
  for _, vector in ipairs(vectors) do
    local key = bytes.from_hex(vector.key)
    local nonce = bytes.from_hex(vector.nonce)
    local aad = vector.aad_bytes or (vector.aad and bytes.from_hex(vector.aad))
    local plaintext = bytes.from_hex(vector.plaintext)
    local sealed = bytes.from_hex(vector.sealed)
    check(vector.name .. " [encrypt]", function()
      return aes_ccm.encrypt(key, nonce, plaintext, aad, vector.tag_length) == sealed
    end)
    check(vector.name .. " [decrypt]", function()
      return aes_ccm.decrypt(key, nonce, sealed, aad, vector.tag_length) == plaintext
    end)
  end

  print("\nRunning AES-CCM functional tests...")
  local key = bytes.from_hex("101112131415161718191a1b1c1d1e1f")
  local nonce = bytes.from_hex("c0c1c2c3c4c5c6c7c8c9cacb")
  local aad = "associated data"
  local plaintext = "a message that spans more than one AES block"
  local sealed = aes_ccm.encrypt(key, nonce, plaintext, aad)

  check("default tag length is 16", #sealed == #plaintext + 16)
  check("nil and empty aad are the same", function()
    return aes_ccm.encrypt(key, nonce, plaintext) == aes_ccm.encrypt(key, nonce, plaintext, "")
  end)
  check("tampered tag is rejected", function()
    return aes_ccm.decrypt(key, nonce, string_sub(sealed, 1, -2) .. string_char(255 - string_byte(sealed, -1)), aad)
      == nil
  end)
  check("tampered ciphertext is rejected", function()
    return aes_ccm.decrypt(key, nonce, string_char(255 - string_byte(sealed, 1)) .. string_sub(sealed, 2), aad) == nil
  end)
  check("wrong aad is rejected", aes_ccm.decrypt(key, nonce, sealed, "other data") == nil)
  check("missing aad is rejected", aes_ccm.decrypt(key, nonce, sealed) == nil)
  check("wrong nonce is rejected", function()
    return aes_ccm.decrypt(key, bytes.from_hex("c0c1c2c3c4c5c6c7c8c9cacc"), sealed, aad) == nil
  end)
  check("wrong key is rejected", function()
    return aes_ccm.decrypt(string_rep("\0", 16), nonce, sealed, aad) == nil
  end)
  check("wrong tag length is rejected", aes_ccm.decrypt(key, nonce, sealed, aad, 8) == nil)
  check("every even tag length round-trips", function()
    for tag_length = 4, 16, 2 do
      local out = aes_ccm.encrypt(key, nonce, plaintext, aad, tag_length)
      if #out ~= #plaintext + tag_length or aes_ccm.decrypt(key, nonce, out, aad, tag_length) ~= plaintext then
        return false
      end
    end
    return true
  end)
  check("bad key sizes raise", raises(aes_ccm.encrypt, string_rep("k", 15), nonce, plaintext))
  check("nonces outside 7-13 bytes raise", function()
    return raises(aes_ccm.encrypt, key, string_rep("n", 6), plaintext)
      and raises(aes_ccm.encrypt, key, string_rep("n", 14), plaintext)
      and raises(aes_ccm.decrypt, key, string_rep("n", 6), sealed)
  end)
  check("odd, short and long tag lengths raise", function()
    return raises(aes_ccm.encrypt, key, nonce, plaintext, aad, 5)
      and raises(aes_ccm.encrypt, key, nonce, plaintext, aad, 2)
      and raises(aes_ccm.encrypt, key, nonce, plaintext, aad, 18)
  end)
  check("input shorter than the tag raises", raises(aes_ccm.decrypt, key, nonce, string_rep("x", 15), aad))
  check("a message too long for a 13-byte nonce raises", function()
    return raises(aes_ccm.encrypt, key, string_rep("n", 13), string_rep("x", 65536))
      and pcall(aes_ccm.encrypt, key, string_rep("n", 12), string_rep("x", 65536))
  end)

  -- Stand-in for lua-openssl's cipher table, built on the pure-Lua core so it
  -- passes Feature.ECB and computes real AES, and recording every call. It is
  -- what lets a host without the binding run aes_core's OpenSSL branch.
  print("\nRunning AES-CCM OpenSSL routing against a stand-in binding...")
  local saved_use = openssl_wrapper.enabled()
  local saved_loaded = package.loaded["openssl"]
  local saved_preload = package.preload["openssl"]
  local calls, widest, padded = 0, 0, false
  package.loaded["openssl"] = {
    version = function()
      return "0.8.5"
    end,
    cipher = {
      get = function(name)
        local bits = tonumber(string.match(name, "^aes%-(%d+)%-ecb$"))
        if bits == nil then
          return nil
        end
        return {
          encrypt = function(_, data, cipher_key, _, pad)
            assert(#cipher_key == bits / 8, "stand-in: key size does not match the cipher name")
            calls = calls + 1
            widest = math.max(widest, #data)
            padded = padded or pad ~= false
            local expanded, nr = aes_core.expand_key(cipher_key)
            local out = {}
            for i = 1, #data, 16 do
              out[#out + 1] = aes_core.encrypt_block(string_sub(data, i, i + 15), expanded, nr)
            end
            return table_concat(out)
          end,
        }
      end,
    },
  }
  package.preload["openssl"] = nil
  openssl_wrapper.use(true)

  check("stand-in binding passes Feature.ECB", openssl_wrapper.get(openssl_wrapper.Feature.ECB) ~= nil)
  local vector = test_vectors[1]
  calls, widest = 0, 0
  check("RFC 3610 packet vector #1 through the OpenSSL path", function()
    return aes_ccm.encrypt(
      bytes.from_hex(vector.key),
      bytes.from_hex(vector.nonce),
      bytes.from_hex(vector.plaintext),
      bytes.from_hex(vector.aad),
      vector.tag_length
    ) == bytes.from_hex(vector.sealed)
  end)
  -- 23-byte message: B_0, one AAD block and two message blocks for the MAC,
  -- then S_0, S_1 and S_2 together.
  check("CTR keystream goes to OpenSSL as one call", calls == 5 and widest == 48)
  check("OpenSSL is always asked for no padding", not padded)
  check("AES-256 selects aes-256-ecb", function()
    local key256 = string_rep("\1", 32)
    local out = aes_ccm.encrypt(key256, nonce, plaintext, aad)
    return aes_ccm.decrypt(key256, nonce, out, aad) == plaintext
  end)

  package.loaded["openssl"] = saved_loaded
  package.preload["openssl"] = saved_preload
  openssl_wrapper.use(saved_use)

  print(string.format("\nAES-CCM result: %d/%d tests passed\n", passed, total))
  return passed == total
end

--- Run performance benchmarks for AES-CCM.
function aes_ccm.benchmark()
  local key128 = bytes.from_hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
  local key256 = string_rep("\7", 32)
  local nonce = bytes.from_hex("c0c1c2c3c4c5c6c7c8c9cacb")
  local aad = string_rep("h", 16)
  local plaintext_64 = string_rep("a", 64)
  local plaintext_1k = string_rep("a", 1024)
  local sealed_1k = aes_ccm.encrypt(key128, nonce, plaintext_1k, aad)

  local accelerated = openssl_wrapper.get(openssl_wrapper.Feature.ECB) ~= nil
  print("AES-CCM (" .. (accelerated and "OpenSSL ECB" or "pure Lua") .. "):")
  benchmark_op("aes128_encrypt_64_bytes", function()
    aes_ccm.encrypt(key128, nonce, plaintext_64, aad)
  end, 200)
  benchmark_op("aes128_encrypt_1k", function()
    aes_ccm.encrypt(key128, nonce, plaintext_1k, aad)
  end, 50)
  benchmark_op("aes128_decrypt_1k", function()
    aes_ccm.decrypt(key128, nonce, sealed_1k, aad)
  end, 50)
  benchmark_op("aes256_encrypt_1k", function()
    aes_ccm.encrypt(key256, nonce, plaintext_1k, aad)
  end, 50)
end

return aes_ccm
