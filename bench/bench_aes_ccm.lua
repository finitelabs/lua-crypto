local aes_ccm = require("crypto.aes_ccm")
local utils = require("crypto.utils")
local bytes = utils.bytes
local string_rep = string.rep

local openssl_wrapper = require("crypto.openssl_wrapper")

local benchmark_op = require("benchmark").benchmark_op

--- Run performance benchmarks for AES-CCM.
local function benchmark()
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

return benchmark
