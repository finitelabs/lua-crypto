local ed25519 = require("crypto.ed25519")
local bit32 = require("bitn").bit32
local bit32_raw_bxor = bit32.raw_bxor
local floor = math.floor
local string_byte = string.byte
local string_char = string.char
local string_sub = string.sub
local L = {
  0xed,
  0xd3,
  0xf5,
  0x5c,
  0x1a,
  0x63,
  0x12,
  0x58,
  0xd6,
  0x9c,
  0xf7,
  0xa2,
  0xde,
  0xf9,
  0xde,
  0x14,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0x10,
}
local string_to_bytes = ed25519._internal.string_to_bytes
local bytes_to_string = ed25519._internal.bytes_to_string

local utils = require("crypto.utils")

local bytes = utils.bytes

local string_rep = string.rep

--- Test vectors from RFC 8032 section 7.1 (Ed25519)
local test_vectors = {
  {
    name = "RFC 8032 TEST 1",
    seed = bytes.from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
    public_key = bytes.from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    message = "",
    signature = bytes.from_hex(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        .. "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ),
  },
  {
    name = "RFC 8032 TEST 2",
    seed = bytes.from_hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
    public_key = bytes.from_hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
    message = bytes.from_hex("72"),
    signature = bytes.from_hex(
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        .. "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    ),
  },
  {
    name = "RFC 8032 TEST 3",
    seed = bytes.from_hex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
    public_key = bytes.from_hex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
    message = bytes.from_hex("af82"),
    signature = bytes.from_hex(
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        .. "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    ),
  },
  {
    name = "RFC 8032 TEST 1024",
    seed = bytes.from_hex("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"),
    public_key = bytes.from_hex("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"),
    message = bytes.from_hex(
      "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
        .. "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
        .. "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
        .. "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
        .. "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
        .. "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
        .. "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
        .. "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
        .. "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
        .. "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
        .. "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
        .. "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
        .. "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
        .. "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
        .. "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
        .. "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
        .. "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
        .. "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
        .. "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
        .. "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
        .. "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
        .. "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
        .. "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
        .. "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
        .. "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
        .. "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
        .. "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
        .. "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
        .. "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
        .. "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
        .. "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
        .. "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"
    ),
    signature = bytes.from_hex(
      "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
        .. "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
    ),
  },
  {
    name = "RFC 8032 TEST SHA(abc)",
    seed = bytes.from_hex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"),
    public_key = bytes.from_hex("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"),
    message = bytes.from_hex(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        .. "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    ),
    signature = bytes.from_hex(
      "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
        .. "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
    ),
  },
}

--- Flip the low bit of one byte of a string (empty strings become a single NUL)
--- @param s string Input string
--- @param index integer 1-based byte index to tamper with
--- @return string tampered Tampered string, guaranteed different from the input
local function flip_bit(s, index)
  if #s == 0 then
    return "\0"
  end
  index = ((index - 1) % #s) + 1
  local b = bit32_raw_bxor(string_byte(s, index), 1)
  return string_sub(s, 1, index - 1) .. string_char(b) .. string_sub(s, index + 1)
end

--- Add the group order L to the 32-byte little-endian S half of a signature
--- @param signature string 64-byte signature
--- @return string tampered Signature whose S component equals S + L (>= L)
local function add_l_to_s(signature)
  local s = string_to_bytes(signature, 33, 32)
  local carry = 0
  for i = 1, 32 do
    local v = s[i] + L[i] + carry
    s[i] = v % 256
    carry = floor(v * 0.00390625)
  end
  return string_sub(signature, 1, 32) .. bytes_to_string(s, 32)
end

--- Run comprehensive self-test with RFC 8032 test vectors and functional tests
---
--- This function validates the Ed25519 implementation against the known-answer
--- test vectors from RFC 8032 section 7.1. ALL tests must pass for the
--- implementation to be considered cryptographically safe.
---
--- @return boolean result True if all tests pass, false otherwise
local function selftest()
  local function test_vectors_suite()
    print("Running Ed25519 test vectors...")
    local passed = 0
    local total = 0

    for i, test in ipairs(test_vectors) do
      print(string.format("Test %d: %s (message %d bytes)", i, test.name, #test.message))

      local checks = {}

      local derived = ed25519.derive_public_key(test.seed)
      checks[1] = { name = "derive_public_key", ok = derived == test.public_key, got = derived, want = test.public_key }

      local signature = ed25519.sign(test.seed, test.message)
      checks[2] = { name = "sign", ok = signature == test.signature, got = signature, want = test.signature }

      local expanded = ed25519.expand_private_key(test.seed)
      local sig_expanded = ed25519.sign_expanded(expanded, test.public_key, test.message)
      checks[3] = {
        name = "sign_expanded matches sign",
        ok = sig_expanded == test.signature and sig_expanded == signature,
        got = sig_expanded,
        want = test.signature,
      }

      checks[4] = {
        name = "verify accepts valid signature",
        ok = ed25519.verify(test.public_key, test.message, test.signature) == true,
      }
      checks[5] = {
        name = "verify rejects flipped message bit",
        ok = ed25519.verify(test.public_key, flip_bit(test.message, 1), test.signature) == false,
      }
      checks[6] = {
        name = "verify rejects flipped signature bit",
        ok = ed25519.verify(test.public_key, test.message, flip_bit(test.signature, 40)) == false,
      }

      for _, check in ipairs(checks) do
        total = total + 1
        if check.ok then
          print("  ✅ PASS: " .. check.name)
          passed = passed + 1
        else
          print("  ❌ FAIL: " .. check.name)
          if check.want then
            print("  Expected: " .. bytes.to_hex(check.want))
            print("  Got:      " .. bytes.to_hex(check.got))
          end
        end
      end
      print()
    end

    print(string.format("Test vectors result: %d/%d tests passed", passed, total))
    print()
    return passed == total
  end

  local function functional_tests()
    print("Running Ed25519 functional tests...")
    local passed = 0
    local total = 0

    local cases = {
      {
        name = "Key generation",
        test = function()
          local seed1, pub1 = ed25519.generate_keypair()
          local seed2, pub2 = ed25519.generate_keypair()
          assert(#seed1 == 32 and #pub1 == 32, "Keys should be 32 bytes")
          assert(seed1 ~= seed2, "Different key generations should produce different seeds")
          assert(pub1 ~= pub2, "Different key generations should produce different public keys")
        end,
      },
      {
        name = "Public key derivation consistency",
        test = function()
          local seed = ed25519.generate_private_key()
          assert(ed25519.derive_public_key(seed) == ed25519.derive_public_key(seed), "Derivation must be deterministic")
        end,
      },
      {
        name = "Expanded key shape and determinism",
        test = function()
          local seed = test_vectors[1].seed
          local expanded = ed25519.expand_private_key(seed)
          assert(#expanded == 64, "Expanded key should be 64 bytes")
          assert(expanded == ed25519.expand_private_key(seed), "Expansion must be deterministic")
          local a1 = string_byte(expanded, 1)
          local a32 = string_byte(expanded, 32)
          assert(a1 % 8 == 0, "Low 3 bits of the scalar must be cleared")
          assert(a32 < 128 and a32 >= 64, "Scalar must have bit 254 set and bit 255 cleared")
        end,
      },
      {
        name = "Sign/verify roundtrip with a generated key",
        test = function()
          local seed, pub = ed25519.generate_keypair()
          local msg = "The quick brown fox jumps over the lazy dog"
          local sig = ed25519.sign(seed, msg)
          assert(#sig == 64, "Signature should be 64 bytes")
          assert(ed25519.verify(pub, msg, sig) == true, "Signature should verify")
          assert(ed25519.verify(pub, msg .. "!", sig) == false, "Modified message must not verify")
        end,
      },
      {
        name = "sign_expanded is byte-identical to sign",
        test = function()
          local seed, pub = ed25519.generate_keypair()
          local expanded = ed25519.expand_private_key(seed)
          for _, msg in ipairs({ "", "a", string_rep("z", 200) }) do
            assert(ed25519.sign_expanded(expanded, pub, msg) == ed25519.sign(seed, msg), "Outputs must match")
          end
        end,
      },
      {
        name = "verify rejects a signature from another key",
        test = function()
          local seed_a = test_vectors[2].seed
          local _, pub_b = ed25519.generate_keypair()
          local msg = "cross-key check"
          assert(ed25519.verify(pub_b, msg, ed25519.sign(seed_a, msg)) == false, "Wrong key must not verify")
        end,
      },
      {
        name = "verify returns false for wrong-length signature",
        test = function()
          local v = test_vectors[3]
          assert(ed25519.verify(v.public_key, v.message, "") == false, "Empty signature must be rejected")
          assert(
            ed25519.verify(v.public_key, v.message, string_sub(v.signature, 1, 63)) == false,
            "Short signature must be rejected"
          )
          assert(ed25519.verify(v.public_key, v.message, v.signature .. "\0") == false, "Long signature is rejected")
        end,
      },
      {
        name = "verify returns false for wrong-length public key",
        test = function()
          local v = test_vectors[3]
          assert(ed25519.verify("", v.message, v.signature) == false, "Empty public key must be rejected")
          assert(
            ed25519.verify(string_sub(v.public_key, 1, 31), v.message, v.signature) == false,
            "Short public key must be rejected"
          )
          assert(ed25519.verify(v.public_key .. "\0", v.message, v.signature) == false, "Long public key is rejected")
        end,
      },
      {
        name = "verify returns false for undecodable public key",
        test = function()
          local v = test_vectors[3]
          -- y = 2 is not the y-coordinate of any edwards25519 point
          local bad = bytes.from_hex("0200000000000000000000000000000000000000000000000000000000000000")
          assert(ed25519.verify(bad, v.message, v.signature) == false, "Undecodable point must be rejected")
        end,
      },
      {
        name = "verify rejects non-canonical S >= L",
        test = function()
          local v = test_vectors[3]
          local malleable = add_l_to_s(v.signature)
          assert(malleable ~= v.signature, "Tampered signature should differ")
          assert(ed25519.verify(v.public_key, v.message, malleable) == false, "S >= L must be rejected")
        end,
      },
      {
        name = "verify returns false for non-string arguments",
        test = function()
          local v = test_vectors[3]
          --- @diagnostic disable: param-type-mismatch -- the wrong types are the test
          assert(ed25519.verify(nil, v.message, v.signature) == false, "nil public key must be rejected")
          assert(ed25519.verify(v.public_key, nil, v.signature) == false, "nil message must be rejected")
          assert(ed25519.verify(v.public_key, v.message, 42) == false, "non-string signature must be rejected")
          --- @diagnostic enable: param-type-mismatch
        end,
      },
    }

    for _, case in ipairs(cases) do
      total = total + 1
      local success, err = pcall(case.test)
      if success then
        print("  ✅ PASS: " .. case.name)
        passed = passed + 1
      else
        print("  ❌ FAIL: " .. case.name .. " - " .. tostring(err))
      end
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
