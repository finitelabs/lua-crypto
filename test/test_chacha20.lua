local chacha20 = require("crypto.chacha20")
local utils = require("crypto.utils")
local bytes = utils.bytes
local min = math.min
local string_byte = string.byte
local string_char = string.char
local chacha20_block = chacha20._internal.chacha20_block

local string_rep = string.rep

--- Test vectors from RFC 8439
local test_vectors = {
  {
    name = "RFC 8439 Test Vector 1 - ChaCha20 Block Function",
    key = bytes.from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    nonce = bytes.from_hex("000000090000004a00000000"),
    counter = 1,
    plaintext = "", -- Empty for block function test
    expected_keystream = bytes.from_hex(
      "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
    ),
  },
  {
    name = "RFC 8439 Test Vector 2 - ChaCha20 Encryption",
    key = bytes.from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    nonce = bytes.from_hex("000000000000004a00000000"),
    counter = 1,
    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
    expected_ciphertext = bytes.from_hex(
      "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
    ),
  },
  {
    name = "RFC 8439 Test Vector 3 - Key and IV setup",
    key = bytes.from_hex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"),
    nonce = bytes.from_hex("000000000000000000000002"),
    counter = 42,
    plaintext = "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.",
    expected_ciphertext = bytes.from_hex(
      "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1"
    ),
  },
  {
    name = "Zero key test",
    key = string_rep("\0", 32),
    nonce = string_rep("\0", 12),
    counter = 0,
    plaintext = string_rep("\0", 64),
    expected_ciphertext = bytes.from_hex(
      "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
    ),
  },
}

--- Run comprehensive self-test with all standard test vectors
---
--- This function validates the implementation against known test vectors
--- from RFC 8439. ALL tests must pass for the implementation to be
--- considered cryptographically safe.
---
--- @return boolean result True if all tests pass, false otherwise
local function selftest()
  local function test_vectors_suite()
    print("Running ChaCha20 test vectors...")
    local passed = 0
    local total = #test_vectors

    for i, test in ipairs(test_vectors) do
      print(string.format("Test %d: %s", i, test.name))
      if test.expected_keystream then
        assert(
          test.expected_ciphertext == nil,
          "Test vector cannot have both expected_keystream and expected_ciphertext"
        )
        -- Test keystream generation
        local keystream = chacha20_block(test.key, test.nonce, test.counter)

        if keystream == test.expected_keystream then
          print("  ✅ PASS: " .. test.name)
          passed = passed + 1
        else
          print("  ❌ FAIL: " .. test.name)
          print("  Expected keystream length:", #test.expected_keystream)
          print("  Got keystream length:     ", #keystream)

          -- Show first few bytes for debugging
          local expected_hex = ""
          local result_hex = ""
          local show_bytes = min(16, #test.expected_keystream)

          for j = 1, show_bytes do
            expected_hex = expected_hex .. string.format("%02x", string_byte(assert(test.expected_keystream), j))
            result_hex = result_hex .. string.format("%02x", string_byte(keystream, j))
          end

          print("  Expected (first " .. show_bytes .. " bytes): " .. expected_hex)
          print("  Got (first " .. show_bytes .. " bytes):      " .. result_hex)
        end
      elseif test.expected_ciphertext then
        assert(
          test.expected_keystream == nil,
          "Test vector cannot have both expected_keystream and expected_ciphertext"
        )
        -- Test encryption
        local result = chacha20.crypt(test.key, test.nonce, test.plaintext, test.counter)

        if result == test.expected_ciphertext then
          print("  ✅ PASS: " .. test.name)
          passed = passed + 1
        else
          print("  ❌ FAIL: " .. test.name)
          print("  Expected ciphertext length:", #test.expected_ciphertext)
          print("  Got ciphertext length:     ", #result)

          -- Show first few bytes for debugging
          local expected_hex = ""
          local result_hex = ""
          local show_bytes = min(16, #test.expected_ciphertext)

          for j = 1, show_bytes do
            expected_hex = expected_hex .. string.format("%02x", string_byte(assert(test.expected_ciphertext), j))
            result_hex = result_hex .. string.format("%02x", string_byte(result, j))
          end

          print("  Expected (first " .. show_bytes .. " bytes): " .. expected_hex)
          print("  Got (first " .. show_bytes .. " bytes):      " .. result_hex)
        end
      else
        error("Test vector must have either expected_keystream or expected_ciphertext")
      end
      print()
    end

    print(string.format("Test vectors result: %d/%d tests passed", passed, total))
    print()
    return passed == total
  end

  local function functional_tests()
    print("Running ChaCha20 functional tests...")
    local passed = 0
    local total = 0

    -- Test 1: Basic encryption/decryption
    total = total + 1
    local key = string_rep(string_char(0x42), 32)
    local nonce = string_rep("\0", 12)
    local counter = 1
    local plaintext = "Hello, ChaCha20! This is a test message for encryption."

    local ciphertext = chacha20.encrypt(key, nonce, plaintext, counter)
    local decrypted = chacha20.decrypt(key, nonce, ciphertext, counter)

    if plaintext == decrypted then
      print("  ✅ PASS: Basic encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Basic encryption/decryption")
    end

    -- Test 2: Encryption is deterministic
    total = total + 1
    local ciphertext2 = chacha20.encrypt(key, nonce, plaintext, counter)

    if ciphertext == ciphertext2 then
      print("  ✅ PASS: Encryption is deterministic")
      passed = passed + 1
    else
      print("  ❌ FAIL: Encryption is not deterministic")
    end

    -- Test 3: Different nonces produce different output
    total = total + 1
    local nonce2 = string_char(0x01) .. string_rep("\0", 11)
    local ciphertext3 = chacha20.encrypt(key, nonce2, plaintext, counter)

    if ciphertext ~= ciphertext3 then
      print("  ✅ PASS: Different nonces produce different ciphertexts")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different nonces produce same ciphertext")
    end

    -- Test 4: Different counters produce different output
    total = total + 1
    local ciphertext4 = chacha20.encrypt(key, nonce, plaintext, 2)

    if ciphertext ~= ciphertext4 then
      print("  ✅ PASS: Different counters produce different ciphertexts")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different counters produce same ciphertext")
    end

    -- Test 5: Empty plaintext
    total = total + 1
    local empty_ct = chacha20.encrypt(key, nonce, "", counter)
    local empty_pt = chacha20.decrypt(key, nonce, empty_ct, counter)

    if empty_pt == "" then
      print("  ✅ PASS: Empty plaintext encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Empty plaintext encryption/decryption")
    end

    -- Test 6: Large plaintext (multi-block)
    total = total + 1
    local large_plaintext = string_rep("A", 256) -- 4 blocks
    local large_ct = chacha20.encrypt(key, nonce, large_plaintext, counter)
    local large_pt = chacha20.decrypt(key, nonce, large_ct, counter)

    if large_pt == large_plaintext then
      print("  ✅ PASS: Multi-block encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Multi-block encryption/decryption")
    end

    -- Test 7: Partial block
    total = total + 1
    local partial_plaintext = string_rep("B", 100) -- Not a multiple of 64
    local partial_ct = chacha20.encrypt(key, nonce, partial_plaintext, counter)
    local partial_pt = chacha20.decrypt(key, nonce, partial_ct, counter)

    if partial_pt == partial_plaintext then
      print("  ✅ PASS: Partial block encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Partial block encryption/decryption")
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
