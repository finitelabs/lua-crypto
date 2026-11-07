local blake2 = require("crypto.blake2")
local string_rep = string.rep

local benchmark_op = require("benchmark").benchmark_op

--- Run performance benchmarks
---
--- This function runs comprehensive performance benchmarks for BLAKE2 operations
--- including BLAKE2s and BLAKE2b hash computation for various message sizes.
local function benchmark()
  -- Test data
  local message_64 = string_rep("a", 64)
  local message_1k = string_rep("a", 1024)
  local message_8k = string_rep("a", 8192)
  local hmac_key = "benchmark_key"

  print("BLAKE2s Hash Operations:")
  benchmark_op("blake2s_64_bytes", function()
    blake2.blake2s(message_64)
  end, 1000)

  benchmark_op("blake2s_1k", function()
    blake2.blake2s(message_1k)
  end, 200)

  benchmark_op("blake2s_8k", function()
    blake2.blake2s(message_8k)
  end, 50)

  print("\nBLAKE2b Hash Operations:")
  benchmark_op("blake2b_64_bytes", function()
    blake2.blake2b(message_64)
  end, 500)

  benchmark_op("blake2b_1k", function()
    blake2.blake2b(message_1k)
  end, 100)

  benchmark_op("blake2b_8k", function()
    blake2.blake2b(message_8k)
  end, 25)

  print("\nBLAKE2s HMAC Operations:")
  benchmark_op("hmac_blake2s_64_bytes", function()
    blake2.hmac_blake2s(hmac_key, message_64)
  end, 500)

  benchmark_op("hmac_blake2s_1k", function()
    blake2.hmac_blake2s(hmac_key, message_1k)
  end, 100)
end

return benchmark
