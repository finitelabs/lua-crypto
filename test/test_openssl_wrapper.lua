--- Tests for crypto.openssl_wrapper: `make test` runs them, and so does the with-tests build's selftest().

local openssl_wrapper = require("crypto.openssl_wrapper")
local OpenSSLFeature = {
  --- Additional Authenticated Data support for AEAD ciphers (ChaCha20-Poly1305, AES-GCM)
  AAD = "AAD",
  --- Key-derivation primitives (`openssl.kdf`), used to accelerate HKDF
  KDF = "KDF",
  --- Arbitrary-precision integers (`openssl.bn`), used by `crypto.bignum`. The probe only runs
  --- a one-limb powmod; bignum checks each operation it routes on multi-limb values first.
  BN = "BN",
  --- Raw AES-ECB block encryption with padding off (`cipher:encrypt(blocks, key, nil, false)`),
  --- used by `crypto.aes_core` for AES-CCM. The probe checks FIPS-197 known answers.
  ECB = "ECB",
  --- Raw Octet Key Pair support: creating and *signing* with Ed25519/X25519 keys.
  --- Importing such a key is not sufficient; the probe requires a working signature.
  OKP = "OKP",
  --- Cryptographically secure random bytes (`openssl.random`), used by `crypto.random`.
  --- Unlike every other feature here this one has no pure-Lua fallback, so it is
  --- resolved through `get_ungated` rather than `get`.
  RANDOM = "RANDOM",
}
local ECB_PLAINTEXT_HEX = "00112233445566778899aabbccddeeff"
local ECB_KNOWN_ANSWERS = {
  { cipher = "aes-128-ecb", key = "000102030405060708090a0b0c0d0e0f", ciphertext = "69c4e0d86a7b0430d8cdb78070b4c55a" },
  {
    cipher = "aes-192-ecb",
    key = "000102030405060708090a0b0c0d0e0f1011121314151617",
    ciphertext = "dda97ca4864cdfe06eaf70a0ec0d7191",
  },
  {
    cipher = "aes-256-ecb",
    key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ciphertext = "8ea2b7ca516745bfeafc49904b496089",
  },
}
local from_hex = openssl_wrapper._internal.from_hex
local FeatureRequirements = openssl_wrapper._internal.FeatureRequirements

--- Run the feature-gating self-test.
---
--- The gate is exercised against injected stand-in bindings rather than the
--- host's real lua-openssl, so the result is identical on every machine and on
--- hosts with no binding at all. This is a regression test for a gate that
--- silently never opened: `_openssl_module_features` was populated by iterating
--- a string-keyed table with `ipairs`, which visits nothing, so every
--- `get(<feature>)` returned nil and ChaCha20-Poly1305 never used OpenSSL.
---
--- @return boolean result True if all tests pass, false otherwise
local function selftest()
  print("Running OpenSSL feature-gating test vectors...")

  -- Snapshot state so the test cannot disturb a real binding or a caller's flag.
  local saved_use = openssl_wrapper.enabled()
  local saved_loaded = package.loaded["openssl"]
  local saved_preload = package.preload["openssl"]

  --- Install a stand-in binding and force the gate to re-resolve against it.
  --- @param stub table|nil Stand-in module, or nil to simulate an absent binding
  local function install(stub)
    package.loaded["openssl"] = stub
    if stub == nil then
      -- Force require("openssl") to fail regardless of what this host actually
      -- has installed, so the fallback case is deterministic everywhere.
      -- Each selftest stubs the same loader independently, which the language
      -- server reads as redefining one field; that is the intent here.
      --- @diagnostic disable-next-line: duplicate-set-field
      package.preload["openssl"] = function()
        error("simulated absent binding")
      end
    else
      package.preload["openssl"] = nil
    end
    -- Acceleration stays requested in both cases; absence must degrade, not throw.
    openssl_wrapper.use(true)
  end

  --- Build a stand-in binding reporting `version`, with optional capabilities.
  --- @param version string|nil Version string returned by openssl.version()
  --- @param extra table|nil Additional fields (bn, kdf, pkey, ...)
  --- @return table stub
  local function stub_openssl(version, extra)
    local stub = {
      version = function()
        return version
      end,
    }
    for key, value in pairs(extra or {}) do
      stub[key] = value
    end
    return stub
  end

  -- A `bn` table that actually computes, modelling the real binding's shape:
  -- `text` parses big-endian bytes, `tohex` renders hex, and modular
  -- exponentiation is available under a configurable name.
  --- @param name string Which spelling of modular exponentiation to expose
  --- @return table bn
  local function working_bn(name)
    local bn = {
      text = function(str)
        local value = 0
        for i = 1, #str do
          value = value * 256 + string.byte(str, i)
        end
        return value
      end,
      tohex = function(n)
        return string.format("%X", n)
      end,
    }
    bn[name] = function(base, exponent, modulus)
      local result = 1
      for _ = 1, exponent do
        result = (result * base) % modulus
      end
      return result
    end
    return bn
  end

  --- A `cipher` table that answers the ECB probe's FIPS-197 inputs the way the
  --- real binding does with padding off: block for block, nil for anything else.
  --- @param fault string|nil "pad" appends a padding block, "wrong" corrupts the
  ---   first block, "missing_256" has no aes-256-ecb
  --- @return table cipher
  local function ecb_cipher(fault)
    local answers = {}
    for _, answer in ipairs(ECB_KNOWN_ANSWERS) do
      answers[answer.cipher] = answer
    end
    return {
      get = function(name)
        local answer = answers[name]
        if answer == nil or (fault == "missing_256" and name == "aes-256-ecb") then
          return nil
        end
        return {
          encrypt = function(_, data, key, _, pad)
            if key ~= from_hex(answer.key) then
              return nil
            end
            local out = {}
            for i = 1, #data, 16 do
              if data:sub(i, i + 15) ~= from_hex(ECB_PLAINTEXT_HEX) then
                return nil
              end
              out[#out + 1] = from_hex(answer.ciphertext)
            end
            if pad ~= false or fault == "pad" then
              out[#out + 1] = string.rep("\16", 16)
            end
            if fault == "wrong" then
              out[1] = string.rep("\0", 16)
            end
            return table.concat(out)
          end,
        }
      end,
    }
  end

  local tests = {
    {
      name = "version-only feature resolves true on a supporting version",
      test = function()
        install(stub_openssl("0.9.2"))
        return openssl_wrapper.get(OpenSSLFeature.AAD) ~= nil
      end,
    },
    {
      -- Measured on a Control4 controller 2026-08-07: the shipped binding is
      -- lua-openssl 0.8.5, and there `cipher:update(aad, true)` ignores the AAD
      -- flag and encrypts the AAD as plaintext. The 0.9.2 floor is therefore
      -- load-bearing, not decorative, and this case pins it.
      name = "Control4's lua-openssl 0.8.5 does not satisfy AAD",
      test = function()
        install(stub_openssl("0.8.5"))
        return openssl_wrapper.get(OpenSSLFeature.AAD) == nil
      end,
    },
    {
      -- Same binding, but BN is genuinely usable there, so the two features
      -- must resolve differently on one and the same host.
      name = "Control4's lua-openssl 0.8.5 does satisfy BN",
      test = function()
        install(stub_openssl("0.8.5", { bn = working_bn("powmod") }))
        return openssl_wrapper.get(OpenSSLFeature.BN) ~= nil
      end,
    },
    {
      name = "version-only feature resolves false below the minimum",
      test = function()
        install(stub_openssl("0.9.1"))
        return openssl_wrapper.get(OpenSSLFeature.AAD) == nil
      end,
    },
    {
      name = "newer versions still satisfy an older minimum",
      test = function()
        install(stub_openssl("0.10.0"))
        return openssl_wrapper.get(OpenSSLFeature.AAD) ~= nil
      end,
    },
    {
      name = "no features requested returns the module when enabled",
      test = function()
        install(stub_openssl("0.9.2"))
        return openssl_wrapper.get() ~= nil
      end,
    },
    {
      name = "acceleration disabled returns nil even with a supporting binding",
      test = function()
        install(stub_openssl("0.9.2"))
        openssl_wrapper.use(false)
        return openssl_wrapper.get(OpenSSLFeature.AAD) == nil
      end,
    },
    {
      name = "enabled reports what use last set",
      test = function()
        openssl_wrapper.use(true)
        local on = openssl_wrapper.enabled()
        openssl_wrapper.use(false)
        local off = openssl_wrapper.enabled()
        return on == true and off == false
      end,
    },
    {
      name = "absent binding falls back gracefully",
      test = function()
        install(nil)
        return openssl_wrapper.get(OpenSSLFeature.AAD) == nil
      end,
    },
    -- `get` returns the same nil for three unrelated situations. The point of
    -- `unavailable_reason` is that it separates them, so each case is pinned to
    -- the phrase a caller would act on rather than merely to "some string".
    {
      name = "unavailable_reason blames the flag, not the host, when acceleration is off",
      test = function()
        install(stub_openssl("0.9.2"))
        openssl_wrapper.use(false)
        local reason = openssl_wrapper.unavailable_reason(OpenSSLFeature.AAD)
        return type(reason) == "string" and reason:find("crypto.use_openssl(true)", 1, true) ~= nil
      end,
    },
    {
      name = "unavailable_reason blames the host when the binding is absent",
      test = function()
        install(nil)
        local reason = openssl_wrapper.unavailable_reason(OpenSSLFeature.AAD)
        return type(reason) == "string"
          and reason:find("not available", 1, true) ~= nil
          and reason:find("use_openssl", 1, true) == nil
      end,
    },
    {
      name = "unavailable_reason names the feature a present binding lacks",
      test = function()
        install(stub_openssl("0.8.5"))
        local reason = openssl_wrapper.unavailable_reason(OpenSSLFeature.AAD)
        return type(reason) == "string" and reason:find("does not support AAD", 1, true) ~= nil
      end,
    },
    {
      name = "unavailable_reason is nil when the feature is available",
      test = function()
        install(stub_openssl("0.9.2"))
        return openssl_wrapper.unavailable_reason(OpenSSLFeature.AAD) == nil
          and openssl_wrapper.unavailable_reason() == nil
      end,
    },
    {
      name = "BN probe passes when powmod round-trips (Control4 spelling)",
      test = function()
        install(stub_openssl("0.9.2", { bn = working_bn("powmod") }))
        return openssl_wrapper.get(OpenSSLFeature.BN) ~= nil
      end,
    },
    {
      name = "BN probe accepts the mod_exp spelling too",
      test = function()
        install(stub_openssl("0.9.2", { bn = working_bn("mod_exp") }))
        return openssl_wrapper.get(OpenSSLFeature.BN) ~= nil
      end,
    },
    {
      name = "BN probe fails when bn is missing",
      test = function()
        install(stub_openssl("0.9.2"))
        return openssl_wrapper.get(OpenSSLFeature.BN) == nil
      end,
    },
    {
      name = "BN probe fails when the answer is wrong",
      test = function()
        local broken = working_bn("powmod")
        broken.powmod = function()
          return 0
        end
        install(stub_openssl("0.9.2", { bn = broken }))
        return openssl_wrapper.get(OpenSSLFeature.BN) == nil
      end,
    },
    {
      name = "BN probe fails when modular exponentiation raises",
      test = function()
        local raising = working_bn("powmod")
        raising.powmod = function()
          error("not compiled in")
        end
        install(stub_openssl("0.9.2", { bn = raising }))
        return openssl_wrapper.get(OpenSSLFeature.BN) == nil
      end,
    },
    {
      name = "KDF probe requires kdf.derive",
      test = function()
        install(stub_openssl("0.9.2", { kdf = {} }))
        local without = openssl_wrapper.get(OpenSSLFeature.KDF) == nil
        install(stub_openssl("0.9.2", { kdf = { derive = function() end } }))
        return without and openssl_wrapper.get(OpenSSLFeature.KDF) ~= nil
      end,
    },
    {
      name = "OKP probe fails when pkey.new returns nil (Control4 behaviour)",
      test = function()
        install(stub_openssl("0.9.2", {
          pkey = {
            new = function()
              return nil
            end,
          },
        }))
        return openssl_wrapper.get(OpenSSLFeature.OKP) == nil
      end,
    },
    {
      name = "OKP probe fails when sign() returns nil (imported-key behaviour)",
      test = function()
        install(stub_openssl("0.9.2", {
          pkey = {
            new = function()
              return {
                sign = function()
                  return nil
                end,
                verify = function()
                  return true
                end,
              }
            end,
          },
        }))
        return openssl_wrapper.get(OpenSSLFeature.OKP) == nil
      end,
    },
    {
      name = "OKP probe passes only on a full sign/verify round-trip",
      test = function()
        install(stub_openssl("0.9.2", {
          pkey = {
            new = function()
              return {
                sign = function(_, message)
                  return "sig:" .. message
                end,
                verify = function(_, message, signature)
                  return signature == "sig:" .. message
                end,
              }
            end,
          },
        }))
        return openssl_wrapper.get(OpenSSLFeature.OKP) ~= nil
      end,
    },
    {
      name = "all requested features must hold, not just the first",
      test = function()
        install(stub_openssl("0.9.2", { bn = working_bn("powmod") }))
        return openssl_wrapper.get(OpenSSLFeature.AAD, OpenSSLFeature.BN) ~= nil
          and openssl_wrapper.get(OpenSSLFeature.AAD, OpenSSLFeature.KDF) == nil
      end,
    },
    {
      name = "get honours the acceleration flag, get_ungated does not",
      test = function()
        install(stub_openssl("0.9.2", { bn = working_bn("powmod") }))
        openssl_wrapper.use(false)
        -- The flag chooses between two correct implementations, so it must
        -- suppress `get`. It must not be able to suppress a capability that has
        -- no fallback, which is the whole reason `get_ungated` exists.
        return openssl_wrapper.get(OpenSSLFeature.BN) == nil and openssl_wrapper.get_ungated(OpenSSLFeature.BN) ~= nil
      end,
    },
    {
      name = "get_ungated still enforces the probe",
      test = function()
        install(stub_openssl("0.9.2"))
        openssl_wrapper.use(false)
        -- Ungated means "ignore the flag", not "skip the check".
        return openssl_wrapper.get_ungated(OpenSSLFeature.BN) == nil
      end,
    },
    {
      name = "RANDOM probe requires rand_status, a full width, and two distinct draws",
      test = function()
        --- @param overrides table Fields replacing the working RNG stub
        local function rng(overrides)
          local draws = 0
          local stub = {
            rand_status = function()
              return true
            end,
            random = function(n)
              draws = draws + 1
              return string.rep(string.char(draws % 256), n)
            end,
          }
          for key, value in pairs(overrides) do
            stub[key] = value
          end
          install(stub_openssl("0.8.5", stub))
          return openssl_wrapper.get_ungated(OpenSSLFeature.RANDOM) ~= nil
        end

        return rng({}) == true
          -- Missing rand_status: unverifiable seeding is treated as unseeded.
          and rng({ rand_status = false }) == false
          and rng({
            rand_status = function()
              return false
            end,
          }) == false
          -- A constant RNG passes a length check but not a distinctness one.
          and rng({
            random = function(n)
              return string.rep("\0", n)
            end,
          }) == false
          -- A short read must not count as support.
          and rng({
            random = function(n)
              return string.rep("\0", n - 1)
            end,
          }) == false
          and rng({ random = false }) == false
      end,
    },
    {
      -- Measured on a Control4 controller 2026-11-03: the 0.8.5 binding returns
      -- the raw AES block from cipher:encrypt(block, key, nil, false).
      name = "ECB probe passes on FIPS-197 known answers with padding off (Control4 0.8.5)",
      test = function()
        install(stub_openssl("0.8.5", { cipher = ecb_cipher() }))
        return openssl_wrapper.get(OpenSSLFeature.ECB) ~= nil
      end,
    },
    {
      name = "ECB probe fails when a padding block comes back",
      test = function()
        install(stub_openssl("0.9.2", { cipher = ecb_cipher("pad") }))
        return openssl_wrapper.get(OpenSSLFeature.ECB) == nil
      end,
    },
    {
      name = "ECB probe fails on a wrong block",
      test = function()
        install(stub_openssl("0.9.2", { cipher = ecb_cipher("wrong") }))
        return openssl_wrapper.get(OpenSSLFeature.ECB) == nil
      end,
    },
    {
      name = "ECB probe fails when one key size is missing",
      test = function()
        install(stub_openssl("0.9.2", { cipher = ecb_cipher("missing_256") }))
        return openssl_wrapper.get(OpenSSLFeature.ECB) == nil
      end,
    },
    {
      name = "ECB probe fails without cipher.get",
      test = function()
        install(stub_openssl("0.9.2", { cipher = {} }))
        return openssl_wrapper.get(OpenSSLFeature.ECB) == nil
      end,
    },
    {
      name = "unknown features are rejected, not silently granted",
      test = function()
        install(stub_openssl("0.9.2"))
        local ok = pcall(openssl_wrapper.get, "NOT_A_FEATURE")
        return ok == false
      end,
    },
    {
      name = "every declared feature has a requirement entry",
      test = function()
        for _, feature in pairs(OpenSSLFeature) do
          if FeatureRequirements[feature] == nil then
            return false
          end
        end
        return true
      end,
    },
  }

  local passed = 0
  for _, test in ipairs(tests) do
    local ok, result = pcall(test.test)
    if ok and result == true then
      print("  ✅ PASS: " .. test.name)
      passed = passed + 1
    else
      print("  ❌ FAIL: " .. test.name .. (ok and "" or (" - " .. tostring(result))))
    end
  end

  -- Restore the environment for subsequent tests in the same process.
  package.loaded["openssl"] = saved_loaded
  package.preload["openssl"] = saved_preload
  openssl_wrapper.use(saved_use)

  print(string.format("\nOpenSSL feature-gating result: %d/%d tests passed\n", passed, #tests))
  return passed == #tests
end

return selftest
