local chacha20_poly1305 = require("crypto.chacha20_poly1305")
local utils = require("crypto.utils")
local bytes = utils.bytes
local string_rep = string.rep

local benchmark_op = require("benchmark").benchmark_op

--- Run performance benchmarks
---
--- This function runs comprehensive performance benchmarks for ChaCha20-Poly1305 operations
--- including authenticated encryption and decryption for various message sizes.
local function benchmark()
  -- Test data
  local key = bytes.from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
  local nonce = bytes.from_hex("070000004041424344454647")
  local aad = "Additional authenticated data"
  local plaintext_64 = string_rep("a", 64)
  local plaintext_1k = string_rep("a", 1024)
  local plaintext_8k = string_rep("a", 8192)

  print("Authenticated Encryption Operations:")
  benchmark_op("encrypt_64_bytes", function()
    chacha20_poly1305.encrypt(key, nonce, plaintext_64, aad)
  end, 500)

  benchmark_op("encrypt_1k", function()
    chacha20_poly1305.encrypt(key, nonce, plaintext_1k, aad)
  end, 100)

  benchmark_op("encrypt_8k", function()
    chacha20_poly1305.encrypt(key, nonce, plaintext_8k, aad)
  end, 25)

  -- Pre-generate ciphertexts for decryption benchmarks
  local ct_64 = chacha20_poly1305.encrypt(key, nonce, plaintext_64, aad)
  local ct_1k = chacha20_poly1305.encrypt(key, nonce, plaintext_1k, aad)
  local ct_8k = chacha20_poly1305.encrypt(key, nonce, plaintext_8k, aad)

  print("\nAuthenticated Decryption Operations:")
  benchmark_op("decrypt_64_bytes", function()
    chacha20_poly1305.decrypt(key, nonce, ct_64, aad)
  end, 500)

  benchmark_op("decrypt_1k", function()
    chacha20_poly1305.decrypt(key, nonce, ct_1k, aad)
  end, 100)

  benchmark_op("decrypt_8k", function()
    chacha20_poly1305.decrypt(key, nonce, ct_8k, aad)
  end, 25)
end

return benchmark
