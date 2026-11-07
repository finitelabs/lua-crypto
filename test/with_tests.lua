--- Main chunk of build/crypto-tests.lua, the with-tests build: the library, as `require("crypto")`
--- returns it, plus `selftest()` and `benchmark()` over every suite in test/ and bench/.

--- @class crypto.with_tests: crypto
local crypto = require("crypto")

local openssl_wrapper = crypto.openssl_wrapper

-- Parenthesized: from Lua 5.4 on, require returns a second value that a table constructor would keep.
local SELFTESTS = {
  { "sha256", (require("test_sha256")) },
  { "sha512", (require("test_sha512")) },
  { "blake2", (require("test_blake2")) },
  { "chacha20", (require("test_chacha20")) },
  { "chacha20_poly1305", (require("test_chacha20_poly1305")) },
  { "poly1305", (require("test_poly1305")) },
  { "aes_gcm", (require("test_aes_gcm")) },
  { "aes_ccm", (require("test_aes_ccm")) },
  { "hkdf", (require("test_hkdf")) },
  { "pbkdf2", (require("test_pbkdf2")) },
  { "random", (require("test_random")) },
  { "bignum", (require("test_bignum")) },
  { "srp", (require("test_srp")) },
  { "p256", (require("test_p256")) },
  { "spake2plus", (require("test_spake2plus")) },
  { "x25519", (require("test_x25519")) },
  { "x448", (require("test_x448")) },
  { "ed25519", (require("test_ed25519")) },
  { "openssl_wrapper", (require("test_openssl_wrapper")) },
  { "utils_bytes", (require("test_utils_bytes")) },
}

local BENCHMARKS = {
  (require("bench_sha256")),
  (require("bench_sha512")),
  (require("bench_blake2")),
  (require("bench_chacha20")),
  (require("bench_chacha20_poly1305")),
  (require("bench_poly1305")),
  (require("bench_aes_gcm")),
  (require("bench_aes_ccm")),
  (require("bench_hkdf")),
  (require("bench_pbkdf2")),
  (require("bench_bignum")),
  (require("bench_srp")),
  (require("bench_p256")),
  (require("bench_spake2plus")),
  (require("bench_x25519")),
  (require("bench_x448")),
  (require("bench_ed25519")),
}

--- Run every module's known-answer tests.
--- @return boolean ok True if all pass
function crypto.selftest()
  local ok = true
  for _, suite in ipairs(SELFTESTS) do
    local name, selftest = suite[1], suite[2]
    local accelerated = openssl_wrapper.enabled()
    if selftest() == false then
      ok = false
    end
    -- A host that enabled acceleration and then ran this must still have it.
    if openssl_wrapper.enabled() ~= accelerated then
      print("test_" .. name .. " did not restore the OpenSSL acceleration flag")
      ok = false
    end
  end
  return ok
end

--- Run every benchmark.
function crypto.benchmark()
  for _, benchmark in ipairs(BENCHMARKS) do
    benchmark()
  end
end

return crypto
