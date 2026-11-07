--- Tests for crypto.x25519: `make test` runs them, and so does the with-tests build's selftest().

local x25519 = require("crypto.x25519")
local string_byte = string.byte

local utils = require("crypto.utils")

local bytes = utils.bytes

local string_rep = string.rep

--- Test vectors from RFC 7748
local test_vectors = {
  {
    name = "RFC 7748 Test Vector 1",
    scalar = bytes.from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
    u_coord = bytes.from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    expected = bytes.from_hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
  },
  {
    name = "RFC 7748 Test Vector 2",
    scalar = bytes.from_hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
    u_coord = bytes.from_hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
    expected = bytes.from_hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
  },
}

--- Run comprehensive self-test with RFC test vectors and functional tests
---
--- This function validates the X25519 implementation against known test vectors
--- from RFC 7748. ALL tests must pass for the implementation to be
--- considered cryptographically safe.
---
--- @return boolean result True if all tests pass, false otherwise
local function selftest()
  local function test_vectors_suite()
    print("Running X25519 test vectors...")
    local passed = 0
    local total = #test_vectors

    for i, test in ipairs(test_vectors) do
      print(string.format("Test %d: %s", i, test.name))

      local result = x25519.diffie_hellman(test.scalar, test.u_coord)

      if result == test.expected then
        print("  ✅ PASS: " .. test.name)
        passed = passed + 1
      else
        print("  ❌ FAIL: " .. test.name)

        -- Show hex output for debugging
        local result_hex = ""
        local expected_hex = ""
        for j = 1, #result do
          result_hex = result_hex .. string.format("%02x", string_byte(result, j))
        end
        for j = 1, #test.expected do
          expected_hex = expected_hex .. string.format("%02x", string_byte(test.expected, j))
        end
        print("  Expected: " .. expected_hex)
        print("  Got:      " .. result_hex)
      end
      print()
    end

    print(string.format("Test vectors result: %d/%d tests passed", passed, total))
    print()
    return passed == total
  end
  local function functional_tests()
    print("Running X25519 functional tests...")
    local passed = 0
    local total = 0

    -- Test 1: Key generation
    total = total + 1
    local success, err = pcall(function()
      local priv1, pub1 = x25519.generate_keypair()
      local priv2, pub2 = x25519.generate_keypair()

      assert(#priv1 == 32 and #pub1 == 32, "Keys should be 32 bytes")
      assert(priv1 ~= priv2, "Different key generations should produce different keys")
      assert(pub1 ~= pub2, "Different key generations should produce different public keys")
    end)

    if success then
      print("  ✅ PASS: Key generation")
      passed = passed + 1
    else
      print("  ❌ FAIL: Key generation - " .. err)
    end

    -- Test 2: Public key derivation consistency
    total = total + 1
    success, err = pcall(function()
      local priv = x25519.generate_private_key()
      local pub1 = x25519.derive_public_key(priv)
      local pub2 = x25519.derive_public_key(priv)

      assert(pub1 == pub2, "Public key derivation should be deterministic")
    end)

    if success then
      print("  ✅ PASS: Public key derivation consistency")
      passed = passed + 1
    else
      print("  ❌ FAIL: Public key derivation consistency - " .. err)
    end

    -- Test 3: Diffie-Hellman symmetry
    total = total + 1
    success, err = pcall(function()
      local alice_priv, alice_pub = x25519.generate_keypair()
      local bob_priv, bob_pub = x25519.generate_keypair()

      local alice_shared = x25519.diffie_hellman(alice_priv, bob_pub)
      local bob_shared = x25519.diffie_hellman(bob_priv, alice_pub)

      assert(alice_shared == bob_shared, "DH should be symmetric")
      assert(#alice_shared == 32, "Shared secret should be 32 bytes")
    end)

    if success then
      print("  ✅ PASS: Diffie-Hellman symmetry")
      passed = passed + 1
    else
      print("  ❌ FAIL: Diffie-Hellman symmetry - " .. err)
    end

    -- Test 4: Different keys produce different shared secrets
    total = total + 1
    success, err = pcall(function()
      local alice_priv, _alice_pub = x25519.generate_keypair()
      local _bob_priv, bob_pub = x25519.generate_keypair()
      local _charlie_priv, charlie_pub = x25519.generate_keypair()

      local alice_bob = x25519.diffie_hellman(alice_priv, bob_pub)
      local alice_charlie = x25519.diffie_hellman(alice_priv, charlie_pub)

      assert(alice_bob ~= alice_charlie, "Different keys should produce different shared secrets")
    end)

    if success then
      print("  ✅ PASS: Different shared secrets")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different shared secrets - " .. err)
    end

    -- Test 5: Edge case - all zero input (should not fail)
    total = total + 1
    success, err = pcall(function()
      local zero_key = string_rep("\0", 32)
      local priv, _pub = x25519.generate_keypair()

      -- This should not crash, though result may be predictable
      local result = x25519.diffie_hellman(priv, zero_key)
      assert(#result == 32, "Should still produce 32-byte result")
    end)

    if success then
      print("  ✅ PASS: Edge case handling")
      passed = passed + 1
    else
      print("  ❌ FAIL: Edge case handling - " .. err)
    end

    print(string.format("\nFunctional tests result: %d/%d tests passed", passed, total))
    print()
    return passed == total
  end

  local vectors_passed = test_vectors_suite()
  local functional_passed = functional_tests()

  return vectors_passed and functional_passed
end

return selftest
