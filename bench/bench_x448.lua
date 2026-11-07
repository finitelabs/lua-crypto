local x448 = require("crypto.x448")

local utils = require("crypto.utils")

local bytes = utils.bytes

local benchmark_op = require("benchmark").benchmark_op

--- Run performance benchmarks
---
--- This function runs comprehensive performance benchmarks for X448 operations
--- including key generation, public key derivation, and Diffie-Hellman operations.
local function benchmark()
  -- Test data from RFC 7748
  local test_scalar = bytes.from_hex(
    "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121"
      .. "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"
  )
  local test_point = bytes.from_hex(
    "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9"
      .. "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"
  )

  print("Key Operations:")
  benchmark_op("generate_keypair", function()
    x448.generate_keypair()
  end, 5)

  benchmark_op("derive_public_key", function()
    x448.derive_public_key(test_scalar)
  end, 10)

  benchmark_op("diffie_hellman", function()
    x448.diffie_hellman(test_scalar, test_point)
  end, 10)
end

return benchmark
