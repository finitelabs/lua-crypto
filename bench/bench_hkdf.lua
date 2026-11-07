local hkdf = require("crypto.hkdf")
local string_char = string.char
local string_rep = string.rep

local benchmark_op = require("benchmark").benchmark_op

--- Run performance benchmarks for HKDF operations.
local function benchmark()
  local ikm = string_rep(string_char(0x0b), 32)
  local salt = "Pair-Setup-Encrypt-Salt"
  local info = "Pair-Setup-Encrypt-Info"
  local prk512 = hkdf.extract("sha512", salt, ikm)

  print("HKDF Operations:")
  benchmark_op("extract (sha256)", function()
    hkdf.extract("sha256", salt, ikm)
  end, 200)

  benchmark_op("extract (sha512)", function()
    hkdf.extract("sha512", salt, ikm)
  end, 200)

  benchmark_op("expand 32B (sha512)", function()
    hkdf.expand("sha512", prk512, info, 32)
  end, 200)

  benchmark_op("expand 160B (sha512)", function()
    hkdf.expand("sha512", prk512, info, 160)
  end, 100)

  benchmark_op("derive 32B (sha512, HAP shape)", function()
    hkdf.hkdf_sha512(salt, ikm, info, 32)
  end, 100)
end

return benchmark
