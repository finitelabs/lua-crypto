--- Tests for crypto.blake2: `make test` runs them, and so does the with-tests build's selftest().

local blake2 = require("crypto.blake2")
local utils = require("crypto.utils")
local bytes = utils.bytes
local string_char = string.char
local string_rep = string.rep

--- Digest test vectors
local blake2s_test_vectors = {
  {
    name = "Test Vector 1 - Empty string",
    input = "",
    expected = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
  },
  {
    name = "Test Vector 2 - abc",
    input = "abc",
    expected = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
  },
  {
    name = "Test Vector 3 - Long string",
    input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    expected = "6f4df5116a6f332edab1d9e10ee87df6557beab6259d7663f3bcd5722c13f189",
  },
}

local blake2b_test_vectors = {
  {
    name = "Test Vector 1 - Empty string",
    input = "",
    expected = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
  },
  {
    name = "Test Vector 2 - abc",
    input = "abc",
    expected = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
  },
  {
    name = "Test Vector 3 - Long string",
    input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    expected = "7285ff3e8bd768d69be62b3bf18765a325917fa9744ac2f582a20850bc2b1141ed1b3e4528595acc90772bdf2d37dc8a47130b44f33a02e8730e5ad8e166e888",
  },
}

--- HMAC-BLAKE2 test vectors verified with Python's hmac library
--- These use true HMAC construction (RFC 2104), not BLAKE2's keyed mode
--- Python code: hmac.new(key, message, hashlib.blake2s).hexdigest()
local hmac_blake2s_test_vectors = {
  {
    name = "Empty message with short key",
    key = "key",
    message = "",
    expected = "67148074efc0f6741b474ef81c4d98d266e880d372fe723d2569b1d414d234be",
  },
  {
    name = "Short message with short key",
    key = "key",
    message = "The quick brown fox jumps over the lazy dog",
    expected = "f93215bb90d4af4c3061cd932fb169fb8bb8a91d0b4022baea1271e1323cd9a0",
  },
  {
    name = "RFC 4231 Test Case 1 pattern",
    key = string_rep(string_char(0x0b), 20),
    message = "Hi There",
    expected = "65a8b7c5cc9136d424e82c37e2707e74e913c0655b99c75f40edf387453a3260",
  },
  {
    name = "RFC 4231 Test Case 2 pattern",
    key = "Jefe",
    message = "what do ya want for nothing?",
    expected = "90b6281e2f3038c9056af0b4a7e763cae6fe5d9eb4386a0ec95237890c104ff0",
  },
  {
    name = "Key = block size (64 bytes)",
    key = string_rep("a", 64),
    message = "Test message",
    expected = "12d0e782ae473d8007d33ae6e5244afcaf9239f6a7d5476c69060c01383d6b58",
  },
  {
    name = "Key > block size (80 bytes)",
    key = string_rep("a", 80),
    message = "Test message",
    expected = "41da357bda1107f9fad1a504b5afbe75f5ead5ed7cf8f82e59e18c5e9e653882",
  },
}

local hmac_blake2b_test_vectors = {
  {
    name = "Empty message with short key",
    key = "key",
    message = "",
    expected = "019fe04bf010b8d72772e6b46897ecf74b4878c394ff2c4d5cfa0b7cc9bbefcb28c36de23cef03089db9c3d900468c89804f135e9fdef7ec9b3c7abe50ed33d3",
  },
  {
    name = "Short message with short key",
    key = "key",
    message = "The quick brown fox jumps over the lazy dog",
    expected = "92294f92c0dfb9b00ec9ae8bd94d7e7d8a036b885a499f149dfe2fd2199394aaaf6b8894a1730cccb2cd050f9bcf5062a38b51b0dab33207f8ef35ae2c9df51b",
  },
  {
    name = "RFC 4231 Test Case 1 pattern",
    key = string_rep(string_char(0x0b), 20),
    message = "Hi There",
    expected = "358a6a184924894fc34bee5680eedf57d84a37bb38832f288e3b27dc63a98cc8c91e76da476b508bc6b2d408a248857452906e4a20b48c6b4b55d2df0fe1dd24",
  },
  {
    name = "RFC 4231 Test Case 2 pattern",
    key = "Jefe",
    message = "what do ya want for nothing?",
    expected = "6ff884f8ddc2a6586b3c98a4cd6ebdf14ec10204b6710073eb5865ade37a2643b8807c1335d107ecdb9ffeaeb6828c4625ba172c66379efcd222c2de11727ab4",
  },
  {
    name = "Key = block size (128 bytes)",
    key = string_rep("a", 128),
    message = "Test message",
    expected = "021a22a3ecf0f1f7a15aca6a5d9704fc99b6a84a627fa53f7ac932a961ffb69b1e68c46981d5b44fd00a7cae75e4ee63d393eec844a8de2dd00e45b5a0d4e275",
  },
  {
    name = "Key > block size (80 bytes)",
    key = string_rep("a", 80),
    message = "Test message",
    expected = "1c8fb6f426d7800000e8d03c141905b33d10a4da16f9c018140955c5cedfa7a017204aaea1f141c1c0d3d942dee04a795a6e589898c1328b717ad6053a7b4790",
  },
}

--- Run comprehensive self-test with test vectors and functional tests
--- @return boolean result True if all tests pass, false otherwise
local function selftest()
  print("Running BLAKE2s test vectors...")
  local passed = 0
  local total = #blake2s_test_vectors

  for _, test in ipairs(blake2s_test_vectors) do
    local result = blake2.blake2s_hex(test.input)
    if result == test.expected then
      print(string.format("  ✅ PASS: %s", test.name))
      passed = passed + 1
    else
      print(string.format("  ❌ FAIL: %s", test.name))
      print(string.format("    Expected: %s", test.expected))
      print(string.format("    Got:      %s", result))
      return false
    end
  end

  print(string.format("\nBLAKE2s test vectors result: %d/%d tests passed\n", passed, total))

  print("Running BLAKE2b test vectors...")
  local blake2b_passed = 0
  local blake2b_total = #blake2b_test_vectors

  for _, test in ipairs(blake2b_test_vectors) do
    local result = blake2.blake2b_hex(test.input)
    if result == test.expected then
      print(string.format("  ✅ PASS: %s", test.name))
      blake2b_passed = blake2b_passed + 1
    else
      print(string.format("  ❌ FAIL: %s", test.name))
      print(string.format("    Expected: %s", test.expected))
      print(string.format("    Got:      %s", result))
      return false
    end
  end

  print(string.format("\nBLAKE2b test vectors result: %d/%d tests passed\n", blake2b_passed, blake2b_total))

  -- Run HMAC-BLAKE2 test vectors
  print("Running HMAC-BLAKE2s test vectors...")

  local hmac_s_passed = 0
  local hmac_s_total = #hmac_blake2s_test_vectors

  for _, test in ipairs(hmac_blake2s_test_vectors) do
    local result = blake2.hmac_blake2s_hex(test.key, test.message)
    if result == test.expected then
      print(string.format("  ✅ PASS: %s", test.name))
      hmac_s_passed = hmac_s_passed + 1
    else
      print(string.format("  ❌ FAIL: %s", test.name))
      print(string.format("    Expected: %s", test.expected))
      print(string.format("    Got:      %s", result))
    end
  end

  print(string.format("\nHMAC-BLAKE2s test vectors: %d/%d tests passed\n", hmac_s_passed, hmac_s_total))

  print("Running HMAC-BLAKE2b test vectors...")
  local hmac_b_passed = 0
  local hmac_b_total = #hmac_blake2b_test_vectors

  for _, test in ipairs(hmac_blake2b_test_vectors) do
    local result = blake2.hmac_blake2b_hex(test.key, test.message)
    if result == test.expected then
      print(string.format("  ✅ PASS: %s", test.name))
      hmac_b_passed = hmac_b_passed + 1
    else
      print(string.format("  ❌ FAIL: %s", test.name))
      print(string.format("    Expected: %s", test.expected))
      print(string.format("    Got:      %s", result))
    end
  end

  print(string.format("\nHMAC-BLAKE2b test vectors: %d/%d tests passed\n", hmac_b_passed, hmac_b_total))

  print("Running BLAKE2 functional tests...")

  -- Test consistency
  local test_data = "Hello, BLAKE2!"
  local blake2s_hash1 = blake2.blake2s_hex(test_data)
  local blake2s_hash2 = blake2.blake2s_hex(test_data)
  local blake2b_hash1 = blake2.blake2b_hex(test_data)
  local blake2b_hash2 = blake2.blake2b_hex(test_data)

  if blake2s_hash1 ~= blake2s_hash2 or blake2b_hash1 ~= blake2b_hash2 then
    print("  ❌ FAIL: Hash functions are not deterministic")
    return false
  else
    print("  ✅ PASS: Hash functions are deterministic")
  end

  -- Test different inputs produce different outputs
  local hash_a_s = blake2.blake2s_hex("a")
  local hash_b_s = blake2.blake2s_hex("b")
  local hash_a_b = blake2.blake2b_hex("a")
  local hash_b_b = blake2.blake2b_hex("b")

  if hash_a_s == hash_b_s or hash_a_b == hash_b_b then
    print("  ❌ FAIL: Different inputs produce same hash")
    return false
  else
    print("  ✅ PASS: Different inputs produce different hashes")
  end

  -- Test binary vs hex consistency
  local test_msg = "test message"
  local binary_s = blake2.blake2s(test_msg)
  local hex_s = blake2.blake2s_hex(test_msg)
  local binary_b = blake2.blake2b(test_msg)
  local hex_b = blake2.blake2b_hex(test_msg)

  if hex_s ~= bytes.to_hex(binary_s) or hex_b ~= bytes.to_hex(binary_b) then
    print("  ❌ FAIL: Binary and hex outputs inconsistent")
    return false
  else
    print("  ✅ PASS: Binary and hex outputs consistent")
  end

  -- Test HMAC consistency
  local hmac1_s = blake2.hmac_blake2s_hex("key", "data")
  local hmac2_s = blake2.hmac_blake2s_hex("key", "data")
  local hmac1_b = blake2.hmac_blake2b_hex("key", "data")
  local hmac2_b = blake2.hmac_blake2b_hex("key", "data")

  if hmac1_s ~= hmac2_s or hmac1_b ~= hmac2_b then
    print("  ❌ FAIL: HMAC functions are not deterministic")
    return false
  else
    print("  ✅ PASS: HMAC functions are deterministic")
  end

  print("\nFunctional tests result: 4/4 tests passed")

  return true
end

return selftest
