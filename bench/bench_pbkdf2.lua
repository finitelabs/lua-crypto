--- Benchmarks for crypto.pbkdf2: `make bench` runs them, and so does the with-tests build's benchmark().

local pbkdf2 = require("crypto.pbkdf2")

local openssl_wrapper = require("crypto.openssl_wrapper")

local benchmark_op = require("benchmark").benchmark_op

--- Run performance benchmarks for PBKDF2.
local function benchmark()
  print("PBKDF2 (HMAC via " .. (openssl_wrapper.get() ~= nil and "OpenSSL" or "pure Lua") .. "):")
  benchmark_op("sha256, 1000 iterations, 32 bytes", function()
    pbkdf2.derive("sha256", "password", "salt", 1000, 32)
  end, 5)
  benchmark_op("sha512, 100 iterations, 64 bytes", function()
    pbkdf2.derive("sha512", "password", "salt", 100, 64)
  end, 3)
end

return benchmark
