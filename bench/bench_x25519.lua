local x25519 = require("crypto.x25519")

local utils = require("crypto.utils")

local bytes = utils.bytes

local benchmark_op = require("benchmark").benchmark_op

--- Run performance benchmarks
---
--- This function runs comprehensive performance benchmarks for X25519 operations
--- including key generation, public key derivation, and Diffie-Hellman operations.
local function benchmark()
  -- Test data from RFC 7748
  local test_scalar = bytes.from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
  local test_point = bytes.from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")

  print("Key Operations:")
  benchmark_op("generate_keypair", function()
    x25519.generate_keypair()
  end, 20)

  benchmark_op("derive_public_key", function()
    x25519.derive_public_key(test_scalar)
  end, 50)

  benchmark_op("diffie_hellman", function()
    x25519.diffie_hellman(test_scalar, test_point)
  end, 50)
end

return benchmark
