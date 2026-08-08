--- @module "crypto.hkdf"
--- HKDF (HMAC-based Extract-and-Expand Key Derivation Function), RFC 5869.
---
--- Supports SHA-256 and SHA-512. This is a thin layer over the HMAC primitives
--- in `crypto.sha256` / `crypto.sha512`, which already prefer OpenSSL when
--- acceleration is enabled, so HKDF inherits that acceleration without needing
--- a routing decision of its own -- see the note on `openssl.kdf` below.
---
--- @usage
--- local hkdf = require("crypto.hkdf")
---
--- -- one-shot: extract then expand
--- local key = hkdf.derive("sha512", salt, shared_secret, "Pair-Setup-Encrypt-Info", 32)
---
--- -- or the two phases separately, when one PRK feeds several expansions
--- local prk = hkdf.extract("sha512", "Control-Salt", shared_secret)
--- local read_key = hkdf.expand("sha512", prk, "ClientEncrypt-main", 32)
--- local write_key = hkdf.expand("sha512", prk, "ServerEncrypt-main", 32)
---
--- @class crypto.hkdf
local hkdf = {}

local sha256 = require("crypto.sha256")
local sha512 = require("crypto.sha512")

local utils = require("crypto.utils")
local bytes = utils.bytes
local benchmark_op = utils.benchmark.benchmark_op

-- Local references for performance
local string_char = string.char
local string_rep = string.rep
local string_sub = string.sub
local table_concat = table.concat

--- Supported hash functions and their parameters.
---
--- `hmac` takes (key, data) and returns the raw MAC; `length` is HashLen in
--- RFC 5869 terms, which fixes both the PRK size and the 255*HashLen output
--- ceiling.
---
--- @class HkdfHash
--- @field hmac fun(key: string, data: string): string HMAC over this hash
--- @field length integer HashLen in bytes

--- @type table<string, HkdfHash>
local HASHES = {
  sha256 = { hmac = sha256.hmac_sha256, length = 32 },
  sha512 = { hmac = sha512.hmac_sha512, length = 64 },
}

-- Note on routing to `openssl.kdf`:
--
-- The wrapper exposes `Feature.KDF` and the Control4 build has it, but HKDF is
-- deliberately NOT routed there. `hmac_sha256`/`hmac_sha512` already return the
-- OpenSSL result when acceleration is on, so the pure-Lua cost of HKDF is the
-- glue around the HMACs, not the HMACs themselves. A HAP derivation is one
-- extract plus one 32-byte expand, i.e. two HMAC invocations total, so routing
-- it separately would buy nothing measurable while adding a second code path
-- that cannot be exercised on a host without the binding. `Feature.KDF` is
-- declared so the capability is queryable if that trade ever changes.

--- Resolve a hash name to its parameters.
--- @param hash string Hash name: "sha256" or "sha512"
--- @return HkdfHash params
local function resolve_hash(hash)
  local params = HASHES[hash]
  if not params then
    error("Unsupported HKDF hash: " .. tostring(hash) .. ' (expected "sha256" or "sha512")')
  end
  return params
end

--- HKDF-Extract (RFC 5869 section 2.2).
---
--- Concentrates the (possibly non-uniform) input keying material into a
--- pseudorandom key of exactly HashLen bytes.
---
--- @param hash string Hash name: "sha256" or "sha512"
--- @param salt string? Optional salt; an empty or absent salt is replaced by HashLen zero bytes, per the RFC
--- @param ikm string Input keying material
--- @return string prk Pseudorandom key, HashLen bytes
function hkdf.extract(hash, salt, ikm)
  local params = resolve_hash(hash)
  assert(type(ikm) == "string", "ikm must be a string")
  if salt == nil or #salt == 0 then
    salt = string_rep("\0", params.length)
  end
  -- Note the argument order: the salt is the HMAC *key* and the IKM is the data.
  return params.hmac(salt, ikm)
end

--- HKDF-Expand (RFC 5869 section 2.3).
---
--- Stretches a pseudorandom key into `length` bytes of output keying material,
--- bound to the supplied context string.
---
--- @param hash string Hash name: "sha256" or "sha512"
--- @param prk string Pseudorandom key, normally the output of `extract`
--- @param info string? Optional context/application-specific information
--- @param length integer Number of output bytes; must be in 1..255*HashLen
--- @return string okm Output keying material, `length` bytes
function hkdf.expand(hash, prk, info, length)
  local params = resolve_hash(hash)
  assert(type(prk) == "string", "prk must be a string")
  assert(type(length) == "number" and length >= 1 and length % 1 == 0, "length must be a positive integer")
  local max_length = 255 * params.length
  assert(length <= max_length, "length must not exceed 255*HashLen (" .. max_length .. " for " .. hash .. ")")
  info = info or ""

  local blocks = {}
  local previous = ""
  local produced = 0
  local counter = 1
  -- T(0) = "", T(i) = HMAC(PRK, T(i-1) || info || i); OKM is the first L bytes
  -- of T(1) || T(2) || ...
  while produced < length do
    previous = params.hmac(prk, previous .. info .. string_char(counter))
    blocks[counter] = previous
    produced = produced + #previous
    counter = counter + 1
  end

  return string_sub(table_concat(blocks), 1, length)
end

--- HKDF: extract then expand in one call (RFC 5869 section 2).
--- @param hash string Hash name: "sha256" or "sha512"
--- @param salt string? Optional salt
--- @param ikm string Input keying material
--- @param info string? Optional context/application-specific information
--- @param length integer Number of output bytes
--- @return string okm Output keying material, `length` bytes
function hkdf.derive(hash, salt, ikm, info, length)
  return hkdf.expand(hash, hkdf.extract(hash, salt, ikm), info, length)
end

--- HKDF with SHA-256, extract and expand in one call.
--- @param salt string? Optional salt
--- @param ikm string Input keying material
--- @param info string? Optional context information
--- @param length integer Number of output bytes
--- @return string okm Output keying material
function hkdf.hkdf_sha256(salt, ikm, info, length)
  return hkdf.derive("sha256", salt, ikm, info, length)
end

--- HKDF with SHA-512, extract and expand in one call.
--- This is the variant HAP uses throughout Pair-Setup, Pair-Verify and session
--- key derivation.
--- @param salt string? Optional salt
--- @param ikm string Input keying material
--- @param info string? Optional context information
--- @param length integer Number of output bytes
--- @return string okm Output keying material
function hkdf.hkdf_sha512(salt, ikm, info, length)
  return hkdf.derive("sha512", salt, ikm, info, length)
end

-- ============================================================================
-- TEST VECTORS AND VALIDATION
-- ============================================================================

--- SHA-256 vectors are RFC 5869 appendix A, cases A.1 to A.3 verbatim. The
--- RFC's remaining cases (A.4 to A.7) use SHA-1, which this library does not
--- implement, so they are omitted rather than adapted.
---
--- The RFC publishes no SHA-512 vectors. The SHA-512 cases below were generated
--- with Node's `crypto.hkdfSync`, an independent OpenSSL-backed implementation;
--- that generator was first checked against A.1 to A.3 above, so it is a
--- validated oracle rather than an assumed-correct one. The PRK figures come
--- from a separate `crypto.createHmac` call, so extract and expand are pinned
--- independently of each other.
local test_vectors = {
  {
    name = "RFC 5869 A.1 - SHA-256, basic",
    hash = "sha256",
    ikm = string_rep(string_char(0x0b), 22),
    salt = bytes.from_hex("000102030405060708090a0b0c"),
    info = bytes.from_hex("f0f1f2f3f4f5f6f7f8f9"),
    length = 42,
    prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
  },
  {
    name = "RFC 5869 A.2 - SHA-256, longer inputs and output",
    hash = "sha256",
    ikm = bytes.from_hex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        .. "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        .. "404142434445464748494a4b4c4d4e4f"
    ),
    salt = bytes.from_hex(
      "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        .. "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        .. "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    ),
    info = bytes.from_hex(
      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        .. "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        .. "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    ),
    length = 82,
    prk = "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
    okm = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
      .. "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
      .. "cc30c58179ec3e87c14c01d5c1f3434f1d87",
  },
  {
    name = "RFC 5869 A.3 - SHA-256, zero-length salt and info",
    hash = "sha256",
    ikm = string_rep(string_char(0x0b), 22),
    salt = "",
    info = "",
    length = 42,
    prk = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
    okm = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
  },
  {
    name = "SHA-512, A.1 inputs",
    hash = "sha512",
    ikm = string_rep(string_char(0x0b), 22),
    salt = bytes.from_hex("000102030405060708090a0b0c"),
    info = bytes.from_hex("f0f1f2f3f4f5f6f7f8f9"),
    length = 42,
    prk = "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26"
      .. "c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
    okm = "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
  },
  {
    name = "SHA-512, 80-byte inputs, 82-byte output",
    hash = "sha512",
    ikm = bytes.from_hex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        .. "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        .. "404142434445464748494a4b4c4d4e4f"
    ),
    salt = bytes.from_hex(
      "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        .. "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        .. "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    ),
    info = bytes.from_hex(
      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        .. "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        .. "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    ),
    length = 82,
    prk = "35672542907d4e142c00e84499e74e1de08be86535f924e022804ad775dde27e"
      .. "c86cd1e5b7d178c74489bdbeb30712beb82d4f97416c5a94ea81ebdf3e629e4a",
    okm = "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1"
      .. "b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235"
      .. "f6a2056ce3af1de44d572097a8505d9e7a93",
  },
  {
    name = "SHA-512, zero-length salt and info",
    hash = "sha512",
    ikm = string_rep(string_char(0x0b), 22),
    salt = "",
    info = "",
    length = 42,
    prk = "fd200c4987ac491313bd4a2a13287121247239e11c9ef82802044b66ef357e5b"
      .. "194498d0682611382348572a7b1611de54764094286320578a863f36562b0df6",
    okm = "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac",
  },
  {
    name = "SHA-512, multi-block output (L=160 spans 3 blocks)",
    hash = "sha512",
    ikm = string_rep(string_char(0x0b), 22),
    salt = bytes.from_hex("000102030405060708090a0b0c"),
    info = bytes.from_hex("f0f1f2f3f4f5f6f7f8f9"),
    length = 160,
    prk = "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26"
      .. "c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
    okm = "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c148157933"
      .. "8da362cb8d9f925d7cbcce0dff7098769cf15959867d571c1715450cb530137b"
      .. "e3fb62f3cf32b84feba8f1eb1b563e20d9749b8640b8264c4b69b14ad5199115"
      .. "e1d609c83c6940ce5b4214a0c79946983547a35cdcc17e0daf31b647dec0d0e6"
      .. "142b1deaa036b348422068ca66631c0ca5586485a276a4336e1cde0e83159b5",
    -- Note the odd hex-digit alignment above: the literal is concatenated in
    -- 64-char chunks and verified as a whole against the 320-char expectation.
  },
  {
    name = "SHA-512, single-byte output",
    hash = "sha512",
    ikm = string_rep(string_char(0x0b), 22),
    salt = bytes.from_hex("000102030405060708090a0b0c"),
    info = bytes.from_hex("f0f1f2f3f4f5f6f7f8f9"),
    length = 1,
    prk = "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26"
      .. "c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
    okm = "83",
  },
}

--- A reproducible 64-byte stand-in for the SRP shared secret K, used by the HAP
--- vectors below. Defined as SHA-512("FL-3 HKDF test vector K") so the input is
--- checkable rather than an opaque blob.
local HAP_K = bytes.from_hex(
  "5b5f50c034f8f0828d08477b4375da348dc40f84cd11dfd3bd13b9acabd4ca26"
    .. "1adbe603042792d70da90d625ecd52c63672ac835d1d0c297542cf74533d2ff6"
)

--- HAP and Apple Companion derivations, with the exact salt and info strings the
--- protocol uses. These are the derivations the Control4 Plex driver will
--- perform, so a regression in the salt/info handling shows up here as a wrong
--- key rather than as a pairing failure on hardware.
local hap_vectors = {
  {
    name = "HAP Pair-Setup session key",
    salt = "Pair-Setup-Encrypt-Salt",
    info = "Pair-Setup-Encrypt-Info",
    okm = "58c07b44c43ab9dee1997d2755c4dd5a9cef49aa115cf5d04008761a1020924d",
  },
  {
    name = "HAP Pair-Setup controller signing material",
    salt = "Pair-Setup-Controller-Sign-Salt",
    info = "Pair-Setup-Controller-Sign-Info",
    okm = "cef7085a25ab4b1f458a60b3256e2c99ba9fd68d635500de44b1127a6ecc2369",
  },
  {
    name = "HAP Pair-Setup accessory signing material",
    salt = "Pair-Setup-Accessory-Sign-Salt",
    info = "Pair-Setup-Accessory-Sign-Info",
    okm = "9778c08f56e300911cc8a1243eb6c6fb60cb6746cdaf6d50222b864d80193b93",
  },
  {
    name = "HAP Pair-Verify session key",
    salt = "Pair-Verify-Encrypt-Salt",
    info = "Pair-Verify-Encrypt-Info",
    okm = "a5029cacb7d64c6b4e7e56320a0ea8cb9bbf0f715743f03e53c59396fe33252e",
  },
  {
    name = "Companion session key, ClientEncrypt-main",
    salt = "Control-Salt",
    info = "ClientEncrypt-main",
    okm = "e47f11626348e473b07abd0a524d46a76869735feed5511b8f38aa9ecb205042",
  },
  {
    name = "Companion session key, ServerEncrypt-main",
    salt = "Control-Salt",
    info = "ServerEncrypt-main",
    okm = "ff1e61252d02c50c81da50149608d7a103ae82a20b78106c6a16e48cdaeb680a",
  },
}

--- Run comprehensive self-test with RFC 5869 and generated test vectors.
---
--- Validates HKDF-Extract and HKDF-Expand for SHA-256 and SHA-512 against
--- known-answer tests, checks the HAP/Companion derivations the driver depends
--- on, and confirms the documented input-validation behaviour.
---
--- @return boolean result True if all tests pass, false otherwise
function hkdf.selftest()
  local passed = 0
  local total = 0

  --- Record one test result. `result` may be a boolean or a function returning
  --- one; a function that raises counts as a failure rather than aborting the run.
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

  print("Running HKDF test vectors...")
  for _, vector in ipairs(test_vectors) do
    local prk = hkdf.extract(vector.hash, vector.salt, vector.ikm)
    local prk_hex = bytes.to_hex(prk)
    if prk_hex == vector.prk then
      check(vector.name .. " [PRK]", true)
    else
      check(vector.name .. " [PRK]", false)
      print("    expected: " .. vector.prk)
      print("    got:      " .. prk_hex)
    end

    -- Expand from the PRK we just derived, so a broken extract cannot be
    -- masked by expand being fed the published PRK instead.
    local okm_hex = bytes.to_hex(hkdf.expand(vector.hash, prk, vector.info, vector.length))
    if okm_hex == vector.okm then
      check(vector.name .. " [OKM]", true)
    else
      check(vector.name .. " [OKM]", false)
      print("    expected: " .. vector.okm)
      print("    got:      " .. okm_hex)
    end

    -- The one-shot helper must agree with the two-phase form.
    local derived = bytes.to_hex(hkdf.derive(vector.hash, vector.salt, vector.ikm, vector.info, vector.length))
    check(vector.name .. " [derive matches extract+expand]", derived == vector.okm)
  end

  print("\nRunning HAP / Companion derivation vectors...")
  for _, vector in ipairs(hap_vectors) do
    local okm_hex = bytes.to_hex(hkdf.hkdf_sha512(vector.salt, HAP_K, vector.info, 32))
    if okm_hex == vector.okm then
      check(vector.name, true)
    else
      check(vector.name, false)
      print("    expected: " .. vector.okm)
      print("    got:      " .. okm_hex)
    end
  end

  print("\nRunning HKDF functional tests...")

  check("absent salt behaves as a zero-filled HashLen salt", function()
    return hkdf.extract("sha512", nil, "ikm") == hkdf.extract("sha512", string_rep("\0", 64), "ikm")
      and hkdf.extract("sha256", "", "ikm") == hkdf.extract("sha256", string_rep("\0", 32), "ikm")
  end)

  check("absent info behaves as empty info", function()
    return hkdf.expand("sha512", string_rep("k", 64), nil, 32) == hkdf.expand("sha512", string_rep("k", 64), "", 32)
  end)

  check("PRK length equals HashLen", function()
    return #hkdf.extract("sha256", "s", "i") == 32 and #hkdf.extract("sha512", "s", "i") == 64
  end)

  check("output lengths are exact across block boundaries", function()
    local prk = hkdf.extract("sha512", "salt", "ikm")
    for _, length in ipairs({ 1, 63, 64, 65, 127, 128, 129, 200 }) do
      if #hkdf.expand("sha512", prk, "info", length) ~= length then
        return false
      end
    end
    return true
  end)

  check("shorter output is a prefix of longer output", function()
    local prk = hkdf.extract("sha512", "salt", "ikm")
    local long = hkdf.expand("sha512", prk, "info", 160)
    return hkdf.expand("sha512", prk, "info", 32) == string_sub(long, 1, 32)
      and hkdf.expand("sha512", prk, "info", 64) == string_sub(long, 1, 64)
  end)

  check("distinct info yields distinct output from one PRK", function()
    local prk = hkdf.extract("sha512", "Control-Salt", HAP_K)
    return hkdf.expand("sha512", prk, "ClientEncrypt-main", 32) ~= hkdf.expand("sha512", prk, "ServerEncrypt-main", 32)
  end)

  check("maximum permitted length is accepted", function()
    local ok, result = pcall(hkdf.expand, "sha256", string_rep("k", 32), "", 255 * 32)
    return ok and #result == 255 * 32
  end)

  check("length above 255*HashLen is rejected", function()
    return pcall(hkdf.expand, "sha256", string_rep("k", 32), "", 255 * 32 + 1) == false
  end)

  check("zero and negative lengths are rejected", function()
    return pcall(hkdf.expand, "sha512", string_rep("k", 64), "", 0) == false
      and pcall(hkdf.expand, "sha512", string_rep("k", 64), "", -1) == false
  end)

  check("non-integer length is rejected", function()
    return pcall(hkdf.expand, "sha512", string_rep("k", 64), "", 32.5) == false
  end)

  check("unsupported hash name is rejected", function()
    return pcall(hkdf.extract, "sha1", "salt", "ikm") == false
      and pcall(hkdf.derive, "md5", "salt", "ikm", "info", 16) == false
  end)

  print(string.format("\nHKDF result: %d/%d tests passed\n", passed, total))
  return passed == total
end

--- Run performance benchmarks for HKDF operations.
function hkdf.benchmark()
  local ikm = string_rep(string_char(0x0b), 32)
  local salt = "Pair-Setup-Encrypt-Salt"
  local info = "Pair-Setup-Encrypt-Info"
  local prk512 = hkdf.extract("sha512", salt, ikm)

  print("HKDF Operations:")
  benchmark_op("extract (sha256)", function()
    hkdf.extract("sha256", salt, ikm)
  end, 200)

  benchmark_op("extract (sha512)", function()
    hkdf.extract("sha512", salt, ikm)
  end, 200)

  benchmark_op("expand 32B (sha512)", function()
    hkdf.expand("sha512", prk512, info, 32)
  end, 200)

  benchmark_op("expand 160B (sha512)", function()
    hkdf.expand("sha512", prk512, info, 160)
  end, 100)

  benchmark_op("derive 32B (sha512, HAP shape)", function()
    hkdf.hkdf_sha512(salt, ikm, info, 32)
  end, 100)
end

return hkdf
