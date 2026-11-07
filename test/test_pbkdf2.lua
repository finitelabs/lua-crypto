local pbkdf2 = require("crypto.pbkdf2")
local utils = require("crypto.utils")
local bytes = utils.bytes
local string_sub = string.sub

local openssl_wrapper = require("crypto.openssl_wrapper")

--- Known answers. `slow` marks a vector that runs only when this host is fast
--- enough to finish it inside `SLOW_BUDGET_SECONDS`.
---
--- * RFC 7914 section 11: both PBKDF2-HMAC-SHA256 vectors.
--- * PBKDF2-HMAC-SHA512 for "password"/"salt" at 1 and 2 iterations, the set
---   CPython's Lib/test/test_hashlib.py carries (pbkdf2_results["sha512"]).
--- * Embedded NUL bytes and a key that ends mid-block, generated with CPython's
---   hashlib.pbkdf2_hmac, which reproduces every published vector above.
local test_vectors = {
  {
    name = "RFC 7914 section 11, SHA-256, c = 1",
    hash = "sha256",
    password = "passwd",
    salt = "salt",
    iterations = 1,
    key = "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
      .. "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
  },
  {
    name = "RFC 7914 section 11, SHA-256, c = 80000",
    hash = "sha256",
    password = "Password",
    salt = "NaCl",
    iterations = 80000,
    key = "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
      .. "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
    slow = true,
  },
  {
    name = "SHA-512, c = 1 (CPython test_hashlib)",
    hash = "sha512",
    password = "password",
    salt = "salt",
    iterations = 1,
    key = "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
      .. "c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce",
  },
  {
    name = "SHA-512, c = 2 (CPython test_hashlib)",
    hash = "sha512",
    password = "password",
    salt = "salt",
    iterations = 2,
    key = "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c"
      .. "f76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e",
  },
  {
    name = "SHA-256, NUL bytes, c = 2, 40 bytes (hashlib)",
    hash = "sha256",
    password = "pass\0word",
    salt = "sa\0lt",
    iterations = 2,
    key = "aa4399833b716be66298125c3e643697f19ac0a893c1a93ef0665590c0cde81678ed9f5030c7cffd",
  },
  {
    name = "SHA-512, NUL bytes, c = 2, 100 bytes (hashlib)",
    hash = "sha512",
    password = "pass\0word",
    salt = "sa\0lt",
    iterations = 2,
    key = "b10b04b1ec0406c23faa6bc0309a13f6d520ebc223bf096e42f6eaa6b6598f5d"
      .. "c6643beb1f5db291e44287bbe755e281a26a93c6c04dc59017b9da06be3742bf"
      .. "cb0aba9241ebda23ef879883a70a782b915e42e5023c0e9919b9688203bf7e9274b97048",
  },
}

--- How long a `slow` vector may be projected to take before it is skipped. The
--- 80000-iteration vector takes about 1.5 s under LuaJIT or with OpenSSL, and
--- one to several minutes under PUC Lua.
local SLOW_BUDGET_SECONDS = 10

--- Iterations timed to project a slow vector's cost.
local PROBE_ITERATIONS = 50

--- Run the PBKDF2 self-test.
--- @return boolean result True if all tests pass, false otherwise
local function selftest()
  local passed = 0
  local total = 0

  --- Record one result; a function that raises counts as a failure.
  --- @param name string
  --- @param result boolean|fun(): boolean
  local function check(name, result)
    total = total + 1
    if type(result) == "function" then
      local ok, value = pcall(result)
      result = ok and value == true
    end
    if result == true then
      print("  ✅ PASS: " .. name)
      passed = passed + 1
    else
      print("  ❌ FAIL: " .. name)
    end
  end

  print(
    "Running PBKDF2 test vectors (HMAC via " .. (openssl_wrapper.get() ~= nil and "OpenSSL" or "pure Lua") .. ")..."
  )
  for _, vector in ipairs(test_vectors) do
    local expected = bytes.from_hex(vector.key)
    local run = true
    if vector.slow then
      local started = os.clock()
      pbkdf2.derive(vector.hash, vector.password, vector.salt, PROBE_ITERATIONS, #expected)
      local projected = (os.clock() - started) * vector.iterations / PROBE_ITERATIONS
      if projected > SLOW_BUDGET_SECONDS then
        run = false
        print(string.format("  SKIP: %s (about %.0f s on this host)", vector.name, projected))
      end
    end
    if run then
      check(vector.name, function()
        return pbkdf2.derive(vector.hash, vector.password, vector.salt, vector.iterations, #expected) == expected
      end)
    end
  end

  print("\nRunning PBKDF2 functional tests...")
  check("a shorter key is a prefix of a longer one", function()
    local long = pbkdf2.derive("sha256", "pw", "salt", 3, 80)
    return #long == 80 and pbkdf2.derive("sha256", "pw", "salt", 3, 20) == string_sub(long, 1, 20)
  end)
  check("a one-byte key works", function()
    return #pbkdf2.derive("sha512", "pw", "salt", 1, 1) == 1
  end)
  check("unsupported hash raises", function()
    return pcall(pbkdf2.derive, "sha1", "pw", "salt", 1, 20) == false
  end)
  check("zero or fractional iterations raise", function()
    return pcall(pbkdf2.derive, "sha256", "pw", "salt", 0, 32) == false
      and pcall(pbkdf2.derive, "sha256", "pw", "salt", 1.5, 32) == false
  end)
  check("zero length raises", function()
    return pcall(pbkdf2.derive, "sha256", "pw", "salt", 1, 0) == false
  end)
  check("non-string password or salt raises", function()
    --- @diagnostic disable-next-line: param-type-mismatch -- the wrong type is the test
    return pcall(pbkdf2.derive, "sha256", nil, "salt", 1, 32) == false
      --- @diagnostic disable-next-line: param-type-mismatch -- the wrong type is the test
      and pcall(pbkdf2.derive, "sha256", "pw", 7, 1, 32) == false
  end)

  print(string.format("\nPBKDF2 result: %d/%d tests passed\n", passed, total))
  return passed == total
end

return selftest
