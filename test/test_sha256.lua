--- Tests for crypto.sha256: `make test` runs them, and so does the with-tests build's selftest().

local sha256 = require("crypto.sha256")
local utils = require("crypto.utils")
local bytes = utils.bytes
local string_char = string.char
local string_rep = string.rep

--- Test vectors for self-test
local test_vectors = {
  {
    name = "Empty string",
    input = "",
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  },
  {
    name = "Single character 'a'",
    input = "a",
    expected = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
  },
  {
    name = "Short string 'abc'",
    input = "abc",
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  },
  {
    name = "Numeric string '123456'",
    input = "123456",
    expected = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
  },
  {
    name = "Medium length string",
    input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  },
  {
    name = "The quick brown fox",
    input = "The quick brown fox jumps over the lazy dog",
    expected = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
  },
  {
    name = "The quick brown fox (cog)",
    input = "The quick brown fox jumps over the lazy cog",
    expected = "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be",
  },
}

if os.getenv("INCLUDE_SLOW_TESTS") == "1" then
  table.insert(test_vectors, {
    name = "Million 'a' characters",
    input = string_rep("a", 1000000),
    expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
  })
end

--- HMAC test vectors
local hmac_test_vectors = {
  {
    name = "HMAC Test Case 1",
    key = string_rep(string_char(0x0b), 20),
    data = "Hi There",
    expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  },
  {
    name = "HMAC Test Case 2",
    key = "Jefe",
    data = "what do ya want for nothing?",
    expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  },
  {
    name = "HMAC Test Case 3",
    key = string_rep(string_char(0xaa), 20),
    data = string_rep(string_char(0xdd), 50),
    expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
  },
}

--- Run comprehensive self-test with test vectors and functional tests
--- @return boolean result True if all tests pass, false otherwise
local function selftest()
  print("Running SHA-256 test vectors...")
  local all_passed = true
  local passed = 0
  local total = #test_vectors

  for _, test in ipairs(test_vectors) do
    local result = sha256.sha256_hex(test.input)
    if result == test.expected then
      print(string.format("  ✅ PASS: %s", test.name))
      passed = passed + 1
    else
      print(string.format("  ❌ FAIL: %s", test.name))
      print(string.format("    Expected: %s", test.expected))
      print(string.format("    Got:      %s", result))
    end
  end

  print(string.format("\nTest vectors result: %d/%d tests passed\n", passed, total))
  all_passed = all_passed and (passed == total)

  print("Running SHA-256 HMAC test vectors...")
  local hmac_passed = 0
  local hmac_total = #hmac_test_vectors

  for _, test in ipairs(hmac_test_vectors) do
    local result = sha256.hmac_sha256_hex(test.key, test.data)
    if result == test.expected then
      print(string.format("  ✅ PASS: %s", test.name))
      hmac_passed = hmac_passed + 1
    else
      print(string.format("  ❌ FAIL: %s", test.name))
      print(string.format("    Expected: %s", test.expected))
      print(string.format("    Got:      %s", result))
    end
  end

  print(string.format("\nHMAC test vectors result: %d/%d tests passed\n", hmac_passed, hmac_total))
  all_passed = all_passed and (hmac_passed == hmac_total)

  print("Running SHA-256 functional tests...")

  local func_passed = 0
  local func_total = 0

  -- Test consistency
  func_total = func_total + 1
  local test_data = "Hello, World!"
  local hash1 = sha256.sha256_hex(test_data)
  local hash2 = sha256.sha256_hex(test_data)
  if hash1 ~= hash2 then
    print("  ❌ FAIL: Hash function is not deterministic")
  else
    print("  ✅ PASS: Hash function is deterministic")
    func_passed = func_passed + 1
  end

  -- Test different inputs produce different outputs
  func_total = func_total + 1
  local hash_a = sha256.sha256_hex("a")
  local hash_b = sha256.sha256_hex("b")
  if hash_a == hash_b then
    print("  ❌ FAIL: Different inputs produce same hash")
  else
    print("  ✅ PASS: Different inputs produce different hashes")
    func_passed = func_passed + 1
  end

  -- Test binary vs hex consistency
  func_total = func_total + 1
  local test_msg = "test message"
  local binary_hash = sha256.sha256(test_msg)
  local hex_hash = sha256.sha256_hex(test_msg)
  if hex_hash ~= bytes.to_hex(binary_hash) then
    print("  ❌ FAIL: Binary and hex outputs inconsistent")
  else
    print("  ✅ PASS: Binary and hex outputs consistent")
    func_passed = func_passed + 1
  end

  -- Test HMAC consistency
  func_total = func_total + 1
  local hmac1 = sha256.hmac_sha256_hex("key", "data")
  local hmac2 = sha256.hmac_sha256_hex("key", "data")
  if hmac1 ~= hmac2 then
    print("  ❌ FAIL: HMAC function is not deterministic")
  else
    print("  ✅ PASS: HMAC function is deterministic")
    func_passed = func_passed + 1
  end

  -- Test HMAC key sensitivity
  func_total = func_total + 1
  local hmac_key1 = sha256.hmac_sha256_hex("key1", "data")
  local hmac_key2 = sha256.hmac_sha256_hex("key2", "data")
  if hmac_key1 == hmac_key2 then
    print("  ❌ FAIL: Different HMAC keys produce same result")
  else
    print("  ✅ PASS: Different HMAC keys produce different results")
    func_passed = func_passed + 1
  end

  print(string.format("\nFunctional tests result: %d/%d tests passed", func_passed, func_total))

  return all_passed and (func_passed == func_total)
end

return selftest
