local poly1305 = require("crypto.poly1305")
local string_byte = string.byte
local string_char = string.char

local utils = require("crypto.utils")

local bytes = utils.bytes

local string_rep = string.rep

--- Test vectors from RFC 8439, RFC 7539, and other reference implementations
local test_vectors = {
  {
    name = "RFC 8439 Test Vector #1 (all zeros)",
    key = string_rep("\0", 32),
    message = string_rep("\0", 64),
    expected = string_rep("\0", 16),
  },
  {
    name = "RFC 8439 Test Vector #2 (r=0, long message)",
    key = string_rep("\0", 16) .. bytes.from_hex("36e5f6b5c5e06070f0efca96227a863e"),
    message = 'Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an "IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to',
    expected = bytes.from_hex("36e5f6b5c5e06070f0efca96227a863e"),
  },
  {
    name = "RFC 8439 Test Vector #3 (r!=0, s=0)",
    key = bytes.from_hex("36e5f6b5c5e06070f0efca96227a863e") .. string_rep("\0", 16),
    message = 'Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an "IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to',
    expected = bytes.from_hex("f3477e7cd95417af89a6b8794c310cf0"),
  },
  {
    name = "Wrap test vector (tests modular reduction edge case)",
    key = bytes.from_hex("0200000000000000000000000000000000000000000000000000000000000000"),
    message = string_rep(string_char(255), 16),
    expected = bytes.from_hex("03000000000000000000000000000000"),
  },
  {
    name = "RFC 7539 test vector",
    key = bytes.from_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
    message = "Cryptographic Forum Research Group",
    expected = bytes.from_hex("a8061dc1305136c6c22b8baf0c0127a9"),
  },
  {
    name = "NaCl test vector (tests complex multi-block processing)",
    key = bytes.from_hex("eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880"),
    message = bytes.from_hex(
      "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5"
    ),
    expected = bytes.from_hex("f3ffc7703f9400e52a7dfb4b3d3305d9"),
  },
}

--- Run comprehensive self-test with all standard test vectors
---
--- This function validates the implementation against known test vectors
--- from RFCs and reference implementations. ALL tests must pass for the
--- implementation to be considered cryptographically safe.
---
--- @return boolean result True if all tests pass, false otherwise
local function selftest()
  local function test_vectors_suite()
    print("Running Poly1305 test vectors...")
    local passed = 0
    local total = #test_vectors

    for i, test in ipairs(test_vectors) do
      print(string.format("Test %d: %s", i, test.name))

      local result = poly1305.authenticate(test.key, test.message)

      -- Convert results to hex for comparison display
      local result_hex = ""
      local expected_hex = ""

      for j = 1, #result do
        result_hex = result_hex .. string.format("%02x", string_byte(result, j))
      end

      for j = 1, #test.expected do
        expected_hex = expected_hex .. string.format("%02x", string_byte(test.expected, j))
      end

      if result == test.expected then
        print("  ✅ PASS: " .. test.name)
        passed = passed + 1
      else
        print("  ❌ FAIL: " .. test.name)
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
    print("Running Poly1305 functional tests...")
    local passed = 0
    local total = 0

    -- Test 1: Different keys produce different tags
    total = total + 1
    local key1 = string_rep(string_char(0x42), 32)
    local key2 = string_rep(string_char(0x43), 32)
    local message = "Test message for MAC verification"

    local tag1 = poly1305.authenticate(key1, message)
    local tag2 = poly1305.authenticate(key2, message)

    if tag1 ~= tag2 then
      print("  ✅ PASS: Different keys produce different tags")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different keys produce same tag")
    end

    -- Test 2: Different messages produce different tags
    total = total + 1
    local msg1 = "Message 1"
    local msg2 = "Message 2"

    local tag_msg1 = poly1305.authenticate(key1, msg1)
    local tag_msg2 = poly1305.authenticate(key1, msg2)

    if tag_msg1 ~= tag_msg2 then
      print("  ✅ PASS: Different messages produce different tags")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different messages produce same tag")
    end

    -- Test 3: Empty message handling
    total = total + 1
    local empty_tag = poly1305.authenticate(key1, "")

    if #empty_tag == 16 then
      print("  ✅ PASS: Empty message produces valid 16-byte tag")
      passed = passed + 1
    else
      print("  ❌ FAIL: Empty message tag length is not 16 bytes")
    end

    -- Test 4: Large message handling (multi-block)
    total = total + 1
    local large_msg = string_rep("A", 256) -- 16 full blocks
    local large_tag = poly1305.authenticate(key1, large_msg)

    if #large_tag == 16 then
      print("  ✅ PASS: Large message produces valid 16-byte tag")
      passed = passed + 1
    else
      print("  ❌ FAIL: Large message tag length is not 16 bytes")
    end

    -- Test 5: Partial block handling
    total = total + 1
    local partial_msg = string_rep("B", 33) -- 2 blocks + 1 byte
    local partial_tag = poly1305.authenticate(key1, partial_msg)

    if #partial_tag == 16 then
      print("  ✅ PASS: Partial block message produces valid 16-byte tag")
      passed = passed + 1
    else
      print("  ❌ FAIL: Partial block tag length is not 16 bytes")
    end

    -- Test 6: Deterministic MAC
    total = total + 1
    local tag_a = poly1305.authenticate(key1, message)
    local tag_b = poly1305.authenticate(key1, message)

    if tag_a == tag_b then
      print("  ✅ PASS: MAC is deterministic (same input = same output)")
      passed = passed + 1
    else
      print("  ❌ FAIL: MAC is not deterministic")
    end

    -- Test 7: Single byte change detection
    total = total + 1
    local original = "This is a test message"
    local modified = "This is a Test message" -- Changed 't' to 'T'

    local tag_orig = poly1305.authenticate(key1, original)
    local tag_mod = poly1305.authenticate(key1, modified)

    if tag_orig ~= tag_mod then
      print("  ✅ PASS: Single byte change produces different tag")
      passed = passed + 1
    else
      print("  ❌ FAIL: Single byte change not detected")
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
