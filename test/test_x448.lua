--- Tests for crypto.x448: `make test` runs them, and so does the with-tests build's selftest().

local x448 = require("crypto.x448")
local char = string.char
local string_rep = string.rep

local utils = require("crypto.utils")

local bytes = utils.bytes

--- Test vectors from RFC 7748
local test_vectors = {
  {
    name = "RFC 7748 Test Vector 1",
    scalar = bytes.from_hex(
      "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121"
        .. "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"
    ),
    u_coord = bytes.from_hex(
      "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9"
        .. "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"
    ),
    expected = bytes.from_hex(
      "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f"
        .. "e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"
    ),
  },
  {
    name = "RFC 7748 Test Vector 2",
    scalar = bytes.from_hex(
      "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5"
        .. "38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f"
    ),
    u_coord = bytes.from_hex(
      "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b"
        .. "165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db"
    ),
    expected = bytes.from_hex(
      "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7"
        .. "ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"
    ),
  },
}

--- Run comprehensive self-test with RFC test vectors and functional tests
---
--- This function validates the X448 implementation against known test vectors
--- from RFC 7748. ALL tests must pass for the implementation to be
--- considered cryptographically safe.
---
--- @return boolean result True if all tests pass, false otherwise
local function selftest()
  local function test_vectors_suite()
    print("Running X448 test vectors...")
    local passed = 0
    local total = #test_vectors

    for i, test in ipairs(test_vectors) do
      print(string.format("Test %d: %s", i, test.name))

      -- Debug: Check input format
      print("  Scalar length: " .. #test.scalar)
      print("  U-coord length: " .. #test.u_coord)

      local result = x448.diffie_hellman(test.scalar, test.u_coord)

      if result == test.expected then
        print("  ✅ PASS: " .. test.name)
        passed = passed + 1
      else
        print("  ❌ FAIL: " .. test.name)
        print("    Expected: " .. bytes.to_hex(test.expected))
        print("    Got:      " .. bytes.to_hex(result))
      end
    end

    print(string.format("\nTest vectors result: %d/%d tests passed\n", passed, total))
    return passed == total
  end

  local function functional_tests()
    print("Running X448 functional tests...")
    local passed = 0
    local total = 0

    -- Test 1: Key generation
    total = total + 1
    local ok, err = pcall(function()
      local private_key, public_key = x448.generate_keypair()
      assert(#private_key == 56, "Private key should be 56 bytes")
      assert(#public_key == 56, "Public key should be 56 bytes")
    end)
    if ok then
      print("  ✅ PASS: Key generation")
      passed = passed + 1
    else
      print("  ❌ FAIL: Key generation - " .. tostring(err))
    end

    -- Test 2: Public key derivation consistency
    total = total + 1
    ok = pcall(function()
      local private_key = x448.generate_private_key()
      local public_key1 = x448.derive_public_key(private_key)
      local public_key2 = x448.derive_public_key(private_key)
      assert(public_key1 == public_key2, "Public key derivation should be deterministic")
    end)
    if ok then
      print("  ✅ PASS: Public key derivation consistency")
      passed = passed + 1
    else
      print("  ❌ FAIL: Public key derivation consistency")
    end

    -- Test 3: Diffie-Hellman symmetry
    total = total + 1
    ok = pcall(function()
      local alice_private, alice_public = x448.generate_keypair()
      local bob_private, bob_public = x448.generate_keypair()

      local alice_shared = x448.diffie_hellman(alice_private, bob_public)
      local bob_shared = x448.diffie_hellman(bob_private, alice_public)

      assert(alice_shared == bob_shared, "DH key exchange should be symmetric")
    end)
    if ok then
      print("  ✅ PASS: Diffie-Hellman symmetry")
      passed = passed + 1
    else
      print("  ❌ FAIL: Diffie-Hellman symmetry")
    end

    -- Test 4: Different shared secrets
    total = total + 1
    ok = pcall(function()
      local alice_private, _alice_public = x448.generate_keypair()
      local _bob_private, bob_public = x448.generate_keypair()
      local _charlie_private, charlie_public = x448.generate_keypair()

      local alice_bob = x448.diffie_hellman(alice_private, bob_public)
      local alice_charlie = x448.diffie_hellman(alice_private, charlie_public)

      assert(alice_bob ~= alice_charlie, "Different key pairs should produce different shared secrets")
    end)
    if ok then
      print("  ✅ PASS: Different shared secrets")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different shared secrets")
    end

    -- Test 5: Edge case handling
    total = total + 1
    ok = pcall(function()
      -- Test with all-zero public key
      local private_key = x448.generate_private_key()
      local zero_public = string_rep(char(0), 56)
      local shared = x448.diffie_hellman(private_key, zero_public)
      assert(#shared == 56, "Should handle zero public key")
    end)
    if ok then
      print("  ✅ PASS: Edge case handling")
      passed = passed + 1
    else
      print("  ❌ FAIL: Edge case handling")
    end

    print(string.format("\nFunctional tests result: %d/%d tests passed\n", passed, total))
    return passed == total
  end

  -- Run both test suites
  local vectors_pass = test_vectors_suite()
  local functional_pass = functional_tests()

  return vectors_pass and functional_pass
end

return selftest
