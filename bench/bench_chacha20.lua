--- Benchmarks for crypto.chacha20: `make bench` runs them, and so does the with-tests build's benchmark().

local chacha20 = require("crypto.chacha20")
local utils = require("crypto.utils")
local bytes = utils.bytes

local benchmark_op = require("benchmark").benchmark_op

local string_rep = string.rep

--- Run performance benchmarks
---
--- This function runs comprehensive performance benchmarks for ChaCha20 operations
--- including block generation and stream encryption/decryption.
local function benchmark()
  -- Test data
  local key = bytes.from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  local nonce = bytes.from_hex("000000090000004a00000000")
  local plaintext_64 = string_rep("a", 64)
  local plaintext_1k = string_rep("a", 1024)
  local plaintext_8k = string_rep("a", 8192)

  print("Encryption Operations:")
  benchmark_op("encrypt_64_bytes", function()
    chacha20.encrypt(key, nonce, plaintext_64, 1)
  end, 1000)

  benchmark_op("encrypt_1k", function()
    chacha20.encrypt(key, nonce, plaintext_1k, 1)
  end, 200)

  benchmark_op("encrypt_8k", function()
    chacha20.encrypt(key, nonce, plaintext_8k, 1)
  end, 50)
end

return benchmark
