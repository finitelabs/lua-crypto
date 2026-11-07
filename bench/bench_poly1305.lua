local poly1305 = require("crypto.poly1305")

local utils = require("crypto.utils")

local bytes = utils.bytes

local benchmark_op = require("benchmark").benchmark_op

local string_rep = string.rep

--- Run performance benchmarks
---
--- This function runs comprehensive performance benchmarks for Poly1305 operations
--- including MAC computation for various message sizes.
local function benchmark()
  -- Test data
  local key = bytes.from_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
  local message_64 = string_rep("a", 64)
  local message_1k = string_rep("a", 1024)
  local message_8k = string_rep("a", 8192)

  print("MAC Operations:")
  benchmark_op("mac_64_bytes", function()
    poly1305.authenticate(key, message_64)
  end, 1000)

  benchmark_op("mac_1k", function()
    poly1305.authenticate(key, message_1k)
  end, 200)

  benchmark_op("mac_8k", function()
    poly1305.authenticate(key, message_8k)
  end, 50)
end

return benchmark
