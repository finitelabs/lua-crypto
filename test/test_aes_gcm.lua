--- Tests for crypto.aes_gcm: `make test` runs them, and so does the with-tests build's selftest().

local aes_gcm = require("crypto.aes_gcm")
local utils = require("crypto.utils")
local bytes = utils.bytes
local string_char = string.char
local string_rep = string.rep
local string_sub = string.sub

--- Test vectors from NIST SP 800-38D and other sources
local test_vectors = {
  {
    name = "NIST Test Case 1 (AES-128-GCM)",
    key = string_rep("\0", 16),
    nonce = string_rep("\0", 12),
    plaintext = "",
    aad = "",
    ciphertext = "",
    tag = bytes.from_hex("58e2fccefa7e3061367f1d57a4e7455a"),
  },
  {
    name = "NIST Test Case 2 (AES-128-GCM)",
    key = string_rep("\0", 16),
    nonce = string_rep("\0", 12),
    plaintext = string_rep("\0", 16),
    aad = "",
    ciphertext = bytes.from_hex("0388dace60b6a392f328c2b971b2fe78"),
    tag = bytes.from_hex("ab6e47d42cec13bdf53a67b21257bddf"),
  },
  {
    name = "NIST Test Case 3 (AES-128-GCM with AAD)",
    key = bytes.from_hex("feffe9928665731c6d6a8f9467308308"),
    nonce = bytes.from_hex("cafebabefacedbaddecaf888"),
    plaintext = bytes.from_hex(
      "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
    ),
    aad = "",
    ciphertext = bytes.from_hex(
      "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
    ),
    tag = bytes.from_hex("4d5c2af327cd64a62cf35abd2ba6fab4"),
  },
  {
    name = "Roundtrip test with various inputs",
    key = bytes.from_hex("000102030405060708090a0b0c0d0e0f"),
    nonce = bytes.from_hex("000000000000004a00000000"),
    aad = "Additional authenticated data",
    plaintext = "Hello, AES-GCM AEAD!",
  },
}

--- Run comprehensive self-test with test vectors
--- @return boolean result True if all tests pass, false otherwise
local function selftest()
  local function test_vectors_suite()
    print("Running AES-GCM test vectors...")
    local passed = 0
    local total = #test_vectors

    for i, test in ipairs(test_vectors) do
      print(string.format("Test %d: %s", i, test.name))

      if test.ciphertext then
        -- Test with known ciphertext and tag
        local result = aes_gcm.encrypt(test.key, test.nonce, test.plaintext, test.aad)
        local result_ct = string_sub(result, 1, #test.ciphertext)
        local result_tag = string_sub(result, #test.ciphertext + 1)

        if result_ct == test.ciphertext and result_tag == test.tag then
          print("  ✅ PASS: Encryption")

          -- Test decryption
          local decrypted = aes_gcm.decrypt(test.key, test.nonce, result, test.aad)
          if decrypted == test.plaintext then
            print("  ✅ PASS: Decryption")
            passed = passed + 1
          else
            print("  ❌ FAIL: Decryption")
            print("    Expected: " .. bytes.to_hex(test.plaintext))
            print("    Got:      " .. (decrypted and bytes.to_hex(decrypted) or "nil"))
          end
        else
          print("  ❌ FAIL: Encryption")
          print("    Expected CT: " .. bytes.to_hex(test.ciphertext))
          print("    Got CT:      " .. bytes.to_hex(result_ct))
          print("    Expected Tag: " .. (test.tag and bytes.to_hex(test.tag) or "none"))
          print("    Got Tag:      " .. bytes.to_hex(result_tag))
        end
      else
        -- Roundtrip test
        local encrypted = aes_gcm.encrypt(test.key, test.nonce, test.plaintext, test.aad)
        local decrypted = aes_gcm.decrypt(test.key, test.nonce, encrypted, test.aad)

        if decrypted == test.plaintext then
          print("  ✅ PASS: Roundtrip test")
          passed = passed + 1
        else
          print("  ❌ FAIL: Roundtrip test")
          print("    Original:  " .. bytes.to_hex(test.plaintext))
          print("    Decrypted: " .. (decrypted and bytes.to_hex(decrypted) or "nil"))
        end
      end
    end

    print(string.format("\nTest vectors result: %d/%d tests passed\n", passed, total))
    return passed == total
  end

  local function functional_tests()
    print("Running AES-GCM functional tests...")
    local passed = 0
    local total = 0

    -- Test 1: Basic encryption/decryption with AES-128
    total = total + 1
    local key128 = string_rep(string_char(0x42), 16)
    local nonce = string_rep("\0", 11) .. string_char(0x01)
    local aad = "user@example.com|2024-01-01"
    local plaintext = "This is a secret message that needs both encryption and authentication."

    local ciphertext_and_tag = aes_gcm.encrypt(key128, nonce, plaintext, aad)
    local decrypted = aes_gcm.decrypt(key128, nonce, ciphertext_and_tag, aad)

    if decrypted == plaintext then
      print("  ✅ PASS: Basic encryption/decryption (AES-128)")
      passed = passed + 1
    else
      print("  ❌ FAIL: Basic encryption/decryption (AES-128)")
    end

    -- Test 2: Basic encryption/decryption with AES-256
    total = total + 1
    local key256 = string_rep(string_char(0x43), 32)
    local ct256 = aes_gcm.encrypt(key256, nonce, plaintext, aad)
    local pt256 = aes_gcm.decrypt(key256, nonce, ct256, aad)

    if pt256 == plaintext then
      print("  ✅ PASS: Basic encryption/decryption (AES-256)")
      passed = passed + 1
    else
      print("  ❌ FAIL: Basic encryption/decryption (AES-256)")
    end

    -- Test 3: Authentication tag tampering detection
    total = total + 1
    local tampered = ciphertext_and_tag:sub(1, -2) .. string_char(255)
    local tampered_result = aes_gcm.decrypt(key128, nonce, tampered, aad)

    if tampered_result == nil then
      print("  ✅ PASS: Tampered tag correctly rejected")
      passed = passed + 1
    else
      print("  ❌ FAIL: Tampered tag was not detected")
    end

    -- Test 4: Wrong AAD detection
    total = total + 1
    local wrong_aad = "wrong@example.com|2024-01-01"
    local wrong_aad_result = aes_gcm.decrypt(key128, nonce, ciphertext_and_tag, wrong_aad)

    if wrong_aad_result == nil then
      print("  ✅ PASS: Wrong AAD correctly rejected")
      passed = passed + 1
    else
      print("  ❌ FAIL: Wrong AAD was not detected")
    end

    -- Test 5: Nonce uniqueness
    total = total + 1
    local nonce2 = string_rep("\0", 11) .. string_char(0x02)
    local ciphertext2 = aes_gcm.encrypt(key128, nonce2, plaintext, aad)

    if ciphertext_and_tag ~= ciphertext2 then
      print("  ✅ PASS: Different nonces produce different ciphertexts")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different nonces produced same ciphertext")
    end

    -- Test 6: Empty plaintext
    total = total + 1
    local empty_ct = aes_gcm.encrypt(key128, nonce, "", aad)
    local empty_pt = aes_gcm.decrypt(key128, nonce, empty_ct, aad)

    if empty_pt == "" then
      print("  ✅ PASS: Empty plaintext encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Empty plaintext encryption/decryption")
    end

    -- Test 7: Empty AAD
    total = total + 1
    local no_aad_ct = aes_gcm.encrypt(key128, nonce, plaintext, "")
    local no_aad_pt = aes_gcm.decrypt(key128, nonce, no_aad_ct, "")

    if no_aad_pt == plaintext then
      print("  ✅ PASS: Empty AAD encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Empty AAD encryption/decryption")
    end

    -- Test 8: Ciphertext tampering detection
    total = total + 1
    local tampered_ct = string_char(255) .. ciphertext_and_tag:sub(2)
    local tampered_ct_result = aes_gcm.decrypt(key128, nonce, tampered_ct, aad)

    if tampered_ct_result == nil then
      print("  ✅ PASS: Tampered ciphertext correctly rejected")
      passed = passed + 1
    else
      print("  ❌ FAIL: Tampered ciphertext was not detected")
    end

    -- Test 9: Wrong key detection
    total = total + 1
    local wrong_key = string_rep(string_char(0x99), 16)
    local wrong_key_result = aes_gcm.decrypt(wrong_key, nonce, ciphertext_and_tag, aad)

    if wrong_key_result == nil then
      print("  ✅ PASS: Wrong key correctly rejected")
      passed = passed + 1
    else
      print("  ❌ FAIL: Wrong key was not detected")
    end

    -- Test 10: Large plaintext (multiple blocks)
    total = total + 1
    local large_plaintext = string_rep("A", 1000)
    local large_ct = aes_gcm.encrypt(key128, nonce, large_plaintext, aad)
    local large_pt = aes_gcm.decrypt(key128, nonce, large_ct, aad)

    if large_pt == large_plaintext then
      print("  ✅ PASS: Large plaintext encryption/decryption")
      passed = passed + 1
    else
      print("  ❌ FAIL: Large plaintext encryption/decryption")
    end

    -- Test 11: Different key sizes produce different outputs
    total = total + 1
    local key192 = string_rep(string_char(0x44), 24)
    local ct128 = aes_gcm.encrypt(key128, nonce, plaintext, aad)
    local ct192 = aes_gcm.encrypt(key192, nonce, plaintext, aad)
    local ct256_2 = aes_gcm.encrypt(key256, nonce, plaintext, aad)

    if ct128 ~= ct192 and ct192 ~= ct256_2 and ct128 ~= ct256_2 then
      print("  ✅ PASS: Different key sizes produce different outputs")
      passed = passed + 1
    else
      print("  ❌ FAIL: Different key sizes should produce different outputs")
    end

    print(string.format("\nFunctional tests result: %d/%d tests passed\n", passed, total))
    return passed == total
  end

  local vectors_passed = test_vectors_suite()
  local functional_passed = functional_tests()

  return vectors_passed and functional_passed
end

return selftest
