--- Benchmarks for crypto.sha512: `make bench` runs them, and so does the with-tests build's benchmark().

local sha512 = require("crypto.sha512")
local string_rep = string.rep

local benchmark_op = require("benchmark").benchmark_op

--- Run performance benchmarks
---
--- This function runs comprehensive performance benchmarks for SHA-512 operations
--- including hash computation and HMAC for various message sizes.
local function benchmark()
  -- Test data
  local message_64 = string_rep("a", 64)
  local message_1k = string_rep("a", 1024)
  local message_8k = string_rep("a", 8192)
  local hmac_key = "benchmark_key"

  print("Hash Operations:")
  benchmark_op("hash_64_bytes", function()
    sha512.sha512(message_64)
  end, 500)

  benchmark_op("hash_1k", function()
    sha512.sha512(message_1k)
  end, 100)

  benchmark_op("hash_8k", function()
    sha512.sha512(message_8k)
  end, 25)

  print("\nHMAC Operations:")
  benchmark_op("hmac_64_bytes", function()
    sha512.hmac_sha512(hmac_key, message_64)
  end, 250)

  benchmark_op("hmac_1k", function()
    sha512.hmac_sha512(hmac_key, message_1k)
  end, 50)

  benchmark_op("hmac_8k", function()
    sha512.hmac_sha512(hmac_key, message_8k)
  end, 15)
end

return benchmark
