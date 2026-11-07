local p256 = require("crypto.p256")
local utils = require("crypto.utils")
local bytes = utils.bytes
local GX_HEX = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
local GY_HEX = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
local G3_X_HEX = "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c"
local G3_Y_HEX = "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"
local field = p256._internal.field

local benchmark_op = require("benchmark").benchmark_op

-- Multiples of G as uncompressed points, hex. 2G and 3G are the published
-- values above. The RFC 6979 A.2.5 key pair is published there too. The rest
-- were derived with the openssl CLI (OpenSSL 4.1.0): a DER EC key built with
-- `openssl asn1parse -genconf` from the chosen private scalar, whose public
-- point `openssl ec -text` then computes and prints.
local RFC6979_D = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"

local RFC6979_U = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
  .. "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"

-- Compressed encodings printed by `openssl ec -conv_form compressed`.
local COMPRESSED = {
  { name = "G", compressed = "03" .. GX_HEX, point = "04" .. GX_HEX .. GY_HEX },
  { name = "3G (even y)", compressed = "02" .. G3_X_HEX, point = "04" .. G3_X_HEX .. G3_Y_HEX },
  {
    name = "RFC 6979 U",
    compressed = "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
    point = RFC6979_U,
  },
}

--- Run performance benchmarks for P-256.
local function benchmark()
  local k = bytes.from_hex(RFC6979_D)
  local u = assert(p256.decode_point(bytes.from_hex(RFC6979_U)))
  local compressed = bytes.from_hex(COMPRESSED[3].compressed)
  local uncompressed = bytes.from_hex(RFC6979_U)

  print("P-256 (" .. field().name .. "):")
  benchmark_op("mul_base", function()
    p256.mul_base(k)
  end, 5)
  benchmark_op("mul (arbitrary point)", function()
    p256.mul(k, u)
  end, 5)
  benchmark_op("add", function()
    p256.add(u, p256.G)
  end, 50)
  benchmark_op("decode_point (compressed)", function()
    p256.decode_point(compressed)
  end, 20)
  benchmark_op("decode_point (uncompressed)", function()
    p256.decode_point(uncompressed)
  end, 50)
end

return benchmark
