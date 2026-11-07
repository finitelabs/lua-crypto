--- Benchmarks for crypto.aes_gcm: `make bench` runs them, and so does the with-tests build's benchmark().

local aes_gcm = require("crypto.aes_gcm")
local utils = require("crypto.utils")
local bytes = utils.bytes
local string_rep = string.rep

local benchmark_op = require("benchmark").benchmark_op

--- Run performance benchmarks
---
--- This function runs comprehensive performance benchmarks for AES-GCM operations
--- including authenticated encryption and decryption for various message and key sizes.
local function benchmark()
  -- Test data
  local key128 = bytes.from_hex("feffe9928665731c6d6a8f9467308308")
  local key256 = bytes.from_hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
  local nonce = bytes.from_hex("cafebabefacedbaddecaf888")
  local aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2"
  local plaintext_64 = string_rep("a", 64)
  local plaintext_1k = string_rep("a", 1024)
  local plaintext_8k = string_rep("a", 8192)

  print("AES-128-GCM Encryption:")
  benchmark_op("aes128_encrypt_64_bytes", function()
    aes_gcm.encrypt(key128, nonce, plaintext_64, aad)
  end, 200)

  benchmark_op("aes128_encrypt_1k", function()
    aes_gcm.encrypt(key128, nonce, plaintext_1k, aad)
  end, 50)

  benchmark_op("aes128_encrypt_8k", function()
    aes_gcm.encrypt(key128, nonce, plaintext_8k, aad)
  end, 10)

  print("\nAES-256-GCM Encryption:")
  benchmark_op("aes256_encrypt_64_bytes", function()
    aes_gcm.encrypt(key256, nonce, plaintext_64, aad)
  end, 200)

  benchmark_op("aes256_encrypt_1k", function()
    aes_gcm.encrypt(key256, nonce, plaintext_1k, aad)
  end, 50)

  benchmark_op("aes256_encrypt_8k", function()
    aes_gcm.encrypt(key256, nonce, plaintext_8k, aad)
  end, 10)

  -- Pre-generate ciphertexts for decryption benchmarks
  local ct128_64 = aes_gcm.encrypt(key128, nonce, plaintext_64, aad)
  local ct256_1k = aes_gcm.encrypt(key256, nonce, plaintext_1k, aad)

  print("\nDecryption Operations:")
  benchmark_op("aes128_decrypt_64_bytes", function()
    aes_gcm.decrypt(key128, nonce, ct128_64, aad)
  end, 200)

  benchmark_op("aes256_decrypt_1k", function()
    aes_gcm.decrypt(key256, nonce, ct256_1k, aad)
  end, 50)
end

return benchmark
