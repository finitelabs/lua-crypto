--- @module "crypto.pbkdf2"
--- PBKDF2, RFC 8018 section 5.2, over HMAC-SHA256 or HMAC-SHA512.
---
--- A thin layer over the HMAC functions in `crypto.sha256` / `crypto.sha512`,
--- which already run through OpenSSL when acceleration is enabled, so PBKDF2
--- inherits that acceleration without a route of its own, as HKDF does.
---
--- The cost is one HMAC per iteration per output block (32 bytes for SHA-256,
--- 64 for SHA-512). In pure Lua an HMAC-SHA256 takes about 0.01 ms under LuaJIT
--- and 0.6 to 4 ms under PUC Lua 5.1 to 5.5 on a desktop, so a high iteration
--- count is only practical with the JIT or with acceleration on.
---
--- @usage
--- local pbkdf2 = require("crypto.pbkdf2")
--- local key = pbkdf2.derive("sha256", password, salt, 10000, 32)
---
--- @class crypto.pbkdf2
local pbkdf2 = {}

local bit32 = require("bitn").bit32

local openssl_wrapper = require("crypto.openssl_wrapper")
local sha256 = require("crypto.sha256")
local sha512 = require("crypto.sha512")
local utils = require("crypto.utils")
local bytes = utils.bytes
local benchmark_op = utils.benchmark.benchmark_op

-- Local references for performance
local bit32_raw_bxor = bit32.raw_bxor
local ceil = math.ceil
local string_byte = string.byte
local string_char = string.char
local string_sub = string.sub
local table_concat = table.concat

--- A PRF PBKDF2 can use: HMAC over one hash, and that hash's output length.
--- @class Pbkdf2Hash
--- @field hmac fun(key: string, data: string): string HMAC over this hash
--- @field length integer hLen in bytes

--- @type table<string, Pbkdf2Hash>
local HASHES = {
  sha256 = { hmac = sha256.hmac_sha256, length = 32 },
  sha512 = { hmac = sha512.hmac_sha512, length = 64 },
}

--- Derive a key with PBKDF2-HMAC.
---
--- @param hash_name string "sha256" or "sha512"
--- @param password string Password P, any bytes
--- @param salt string Salt S, any bytes
--- @param iterations integer Iteration count c, at least 1
--- @param length integer Derived key length dkLen in bytes, at least 1
--- @return string key `length` bytes
function pbkdf2.derive(hash_name, password, salt, iterations, length)
  local params = HASHES[hash_name]
  if params == nil then
    error("PBKDF2: unsupported hash " .. tostring(hash_name) .. ' (expected "sha256" or "sha512")', 2)
  end
  assert(type(password) == "string", "PBKDF2: password must be a string")
  assert(type(salt) == "string", "PBKDF2: salt must be a string")
  assert(
    type(iterations) == "number" and iterations >= 1 and iterations % 1 == 0,
    "PBKDF2: iterations must be a positive integer"
  )
  assert(type(length) == "number" and length >= 1 and length % 1 == 0, "PBKDF2: length must be a positive integer")

  local hmac = params.hmac
  local hash_length = params.length
  local block_count = ceil(length / hash_length)
  -- RFC 8018 5.2 step 1: the block index is a 32-bit counter.
  assert(block_count <= 4294967295, "PBKDF2: derived key too long")

  local blocks = {}
  for i = 1, block_count do
    -- T_i = U_1 xor U_2 xor ... xor U_c, with U_1 = PRF(P, S || INT(i)).
    local u = hmac(password, salt .. bytes.u32_to_be_bytes(i))
    local t = { string_byte(u, 1, hash_length) }
    for _ = 2, iterations do
      u = hmac(password, u)
      for j = 1, hash_length do
        t[j] = bit32_raw_bxor(t[j], string_byte(u, j))
      end
    end
    local chars = {}
    for j = 1, hash_length do
      chars[j] = string_char(t[j])
    end
    blocks[i] = table_concat(chars)
  end
  return string_sub(table_concat(blocks), 1, length)
end

-- ============================================================================
-- TEST VECTORS AND VALIDATION
-- ============================================================================

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
function pbkdf2.selftest()
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

--- Run performance benchmarks for PBKDF2.
function pbkdf2.benchmark()
  print("PBKDF2 (HMAC via " .. (openssl_wrapper.get() ~= nil and "OpenSSL" or "pure Lua") .. "):")
  benchmark_op("sha256, 1000 iterations, 32 bytes", function()
    pbkdf2.derive("sha256", "password", "salt", 1000, 32)
  end, 5)
  benchmark_op("sha512, 100 iterations, 64 bytes", function()
    pbkdf2.derive("sha512", "password", "salt", 100, 64)
  end, 3)
end

return pbkdf2
