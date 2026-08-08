--- @module "crypto.openssl_wrapper"
--- Optional OpenSSL acceleration with graceful pure-Lua fallback
---
--- This module provides a centralized interface for enabling and accessing OpenSSL
--- acceleration for cryptographic operations. OpenSSL support can be enabled via:
--- 1. Environment variable: CRYPTO_USE_OPENSSL=1 or CRYPTO_USE_OPENSSL=true
--- 2. Calling crypto.use_openssl(true/false) from the main module
---
--- By default, native Lua implementations are used for maximum portability.
--- When OpenSSL is enabled and available, it provides hardware-accelerated
--- implementations for:
--- - SHA256/SHA512 hash functions
--- - BLAKE2s/BLAKE2b hash functions
--- - ChaCha20-Poly1305 AEAD cipher
--- - AES-GCM AEAD cipher
--- - ChaCha20 stream cipher
--- - Big-number modular exponentiation (SRP)
---
--- Note: X25519, X448 and Ed25519 always use the native implementations. The
--- shipped lua-openssl builds cannot perform the raw scalar-multiplication or
--- EdDSA signing operations even when they can import the keys.
--- @class crypto.openssl_wrapper
local openssl_wrapper = {}

--- OpenSSL Feature Enum
---
--- Identifies specific OpenSSL capabilities required by crypto operations.
--- Use these features with `openssl_wrapper.get()` to check if the installed
--- OpenSSL version supports the functionality needed.
---
--- @enum OpenSSLFeature
local OpenSSLFeature = {
  --- Additional Authenticated Data support for AEAD ciphers (ChaCha20-Poly1305, AES-GCM)
  AAD = "AAD",
  --- Key-derivation primitives (`openssl.kdf`), used to accelerate HKDF
  KDF = "KDF",
  --- Arbitrary-precision integers (`openssl.bn`), used to accelerate modular exponentiation
  BN = "BN",
  --- Raw Octet Key Pair support: creating and *signing* with Ed25519/X25519 keys.
  --- Importing such a key is not sufficient; the probe requires a working signature.
  OKP = "OKP",
  --- Cryptographically secure random bytes (`openssl.random`), used by `crypto.random`.
  --- Unlike every other feature here this one has no pure-Lua fallback, so it is
  --- resolved through `get_ungated` rather than `get`.
  RANDOM = "RANDOM",
}

--- Feature requirement definitions
---
--- Each entry declares the minimum lua-openssl version a feature needs and,
--- optionally, a `probe` that confirms the capability is actually present.
--- A version bound alone cannot answer questions like "was this build compiled
--- with `openssl.bn`?", so features whose availability varies between builds of
--- the same version carry a probe. Probes must be side-effect free and are
--- evaluated lazily, at most once per feature, only when that feature is
--- requested.
---
--- @alias FeatureRequirement { min_version: string, probe: (fun(openssl: table): boolean)? }
--- @type table<OpenSSLFeature, FeatureRequirement>
local FeatureRequirements = {
  [OpenSSLFeature.AAD] = { min_version = "0.9.2" },
  [OpenSSLFeature.KDF] = {
    min_version = "0.8.0",
    probe = function(openssl)
      return type(openssl.kdf) == "table" and type(openssl.kdf.derive) == "function"
    end,
  },
  [OpenSSLFeature.BN] = {
    min_version = "0.8.0",
    probe = function(openssl)
      local bn = openssl.bn
      if type(bn) ~= "table" then
        return false
      end
      -- Modular exponentiation is spelled `powmod` on the Control4 build
      -- (lua-openssl 0.8.5, verified on hardware 2026-08-07) and `mod_exp` on
      -- some others, so accept either rather than assuming one name.
      local powmod = type(bn.powmod) == "function" and bn.powmod or bn.mod_exp
      if type(powmod) ~= "function" or type(bn.text) ~= "function" or type(bn.tohex) ~= "function" then
        return false
      end
      -- Exercise the exact conversion path the bignum backend uses -- big-endian
      -- bytes in via bn.text, hex out via bn.tohex -- and require the right
      -- answer. Presence of the names is not proof they are wired up.
      local ok, result = pcall(function()
        local base = bn.text(string.char(0x04))
        local exponent = bn.text(string.char(0x0d))
        local modulus = bn.text(string.char(0x01, 0xf1))
        return bn.tohex(powmod(base, exponent, modulus))
      end)
      -- 4^13 mod 497 == 445 == 0x1BD
      return ok and type(result) == "string" and result:gsub("^0+", ""):lower() == "1bd"
    end,
  },
  [OpenSSLFeature.OKP] = {
    min_version = "0.8.0",
    probe = function(openssl)
      local pkey = openssl.pkey
      if type(pkey) ~= "table" or type(pkey.new) ~= "function" then
        return false
      end
      -- Control4's build returns nil from pkey.new("ed25519"), and even when a
      -- key is imported from DER its sign() yields nil. Only a completed
      -- sign/verify round-trip counts as support.
      local ok, verified = pcall(function()
        local key = pkey.new("ed25519")
        if key == nil then
          return false
        end
        local signature = key:sign("probe")
        if signature == nil then
          return false
        end
        return key:verify("probe", signature) == true
      end)
      return ok and verified == true
    end,
  },
  [OpenSSLFeature.RANDOM] = {
    min_version = "0.8.0",
    probe = function(openssl)
      if type(openssl.random) ~= "function" then
        return false
      end
      -- `rand_status` reports whether the PRNG has been seeded with enough
      -- entropy. A binding that cannot answer the question is treated as
      -- unseeded rather than assumed good -- for entropy the safe default is
      -- "no", because the fallback is a different source, not a slower one.
      if type(openssl.rand_status) ~= "function" then
        return false
      end
      local status_ok, seeded = pcall(openssl.rand_status)
      if not status_ok or seeded ~= true then
        return false
      end
      -- Verify the `strong` flag actually yields the requested width twice, and
      -- that the two draws differ: a build whose RNG is stubbed out or wired to
      -- a constant passes a length check but fails this one. Two equal draws
      -- from a working CSPRNG has probability 2^-256, so the false negative is
      -- not a real risk. Note this consumes entropy, unlike the other probes.
      local first_ok, first = pcall(openssl.random, 32, true)
      if not first_ok or type(first) ~= "string" or #first ~= 32 then
        return false
      end
      local second_ok, second = pcall(openssl.random, 32, true)
      return second_ok and type(second) == "string" and #second == 32 and first ~= second
    end,
  },
}

-- Export Feature enum for external use
openssl_wrapper.Feature = OpenSSLFeature

--- @type table?
local _openssl_module
--- Lazily populated cache of feature support; nil means "not yet resolved".
--- @type table<OpenSSLFeature, boolean>
local _openssl_module_features = {}
--- True once a require("openssl") attempt has failed, to avoid re-probing every call.
local _openssl_unavailable = false
local _use_openssl = os.getenv("CRYPTO_USE_OPENSSL") == "1" or os.getenv("CRYPTO_USE_OPENSSL") == "true"

--- Enable or disable OpenSSL acceleration for cryptographic operations.
--- Enabling is safe even when the lua-openssl binding is absent: accelerated
--- primitives fall back to their pure-Lua implementations automatically.
--- @param use boolean True to enable OpenSSL, false to disable
function openssl_wrapper.use(use)
  _use_openssl = use
  -- Re-probe availability on the next get() so toggling at runtime is safe.
  _openssl_module = nil
  _openssl_module_features = {}
  _openssl_unavailable = false
end

--- Parse semantic version string into comparable components
--- @param version_str string Version string like "0.9.1" or "1.0.0-rc1"
--- @return number major Major version number
--- @return number minor Minor version number
--- @return number patch Patch version number
local function parse_version(version_str)
  local major, minor, patch = version_str:match("(%d+)%.(%d+)%.(%d+)")
  return tonumber(major) or 0, tonumber(minor) or 0, tonumber(patch) or 0
end

--- Compare two semantic versions
--- @param current_version string Current version string
--- @param required_version string Required minimum version string
--- @return boolean supported True if current version >= required version
local function version_supports(current_version, required_version)
  local cur_major, cur_minor, cur_patch = parse_version(current_version)
  local req_major, req_minor, req_patch = parse_version(required_version)

  -- Compare major.minor.patch
  if cur_major > req_major then
    return true
  elseif cur_major == req_major then
    if cur_minor > req_minor then
      return true
    elseif cur_minor == req_minor then
      return cur_patch >= req_patch
    end
  end

  return false
end

--- Resolve whether a single feature is supported by the loaded binding.
--- @param openssl table The loaded lua-openssl module
--- @param feature OpenSSLFeature Feature to resolve
--- @return boolean supported
local function resolve_feature(openssl, feature)
  local requirement = FeatureRequirements[feature]
  if not requirement then
    error("Unknown feature: " .. tostring(feature))
  end

  local current_version = type(openssl.version) == "function" and openssl.version()
  if type(current_version) ~= "string" then
    return false
  end
  if not version_supports(current_version, requirement.min_version) then
    return false
  end
  if requirement.probe then
    local ok, supported = pcall(requirement.probe, openssl)
    return ok and supported == true
  end
  return true
end

--- Load the binding, caching both the module and a failed attempt.
--- @return table|nil openssl
local function load_binding()
  if _openssl_unavailable then
    return nil
  end
  if _openssl_module == nil then
    local ok, openssl_module = pcall(require, "openssl")
    if not ok or openssl_module == nil then
      -- Graceful fallback: acceleration was requested but the binding is absent.
      _openssl_unavailable = true
      return nil
    end
    --- @cast openssl_module table
    _openssl_module = openssl_module
    _openssl_module_features = {}
  end
  return _openssl_module
end

--- Resolve a feature against the loaded binding, caching the verdict.
--- @param openssl table
--- @param feature OpenSSLFeature
--- @return boolean supported
local function supports(openssl, feature)
  local supported = _openssl_module_features[feature]
  if supported == nil then
    supported = resolve_feature(openssl, feature)
    _openssl_module_features[feature] = supported
  end
  return supported
end

--- Get the OpenSSL module if enabled and supports required features
---
--- Checks if OpenSSL is enabled and supports all specified features before
--- returning the module. This ensures that the returned module can safely
--- be used for the requested cryptographic operations.
---
--- @param ... OpenSSLFeature One or more required features that must be supported
--- @return table|nil openssl The OpenSSL module if enabled, available, and supporting all features; nil otherwise
function openssl_wrapper.get(...)
  local required_features = { ... }

  if not _use_openssl then
    return nil
  end
  local openssl = load_binding()
  if openssl == nil then
    return nil
  end
  -- Check all requested features, resolving (and caching) each on first request.
  for _, required_feature in ipairs(required_features) do
    if not supports(openssl, required_feature) then
      return nil
    end
  end
  return openssl
end

--- Get the OpenSSL module for a capability that is *not* an acceleration.
---
--- `get` deliberately honours the opt-in acceleration flag, because every
--- feature behind it has a correct pure-Lua fallback and the flag only chooses
--- which correct implementation runs. `Feature.RANDOM` is different in kind:
--- there is no portable pure-Lua substitute for a CSPRNG, so gating it on a
--- performance switch would silently trade entropy for nothing. Callers that
--- need a capability rather than a speed-up use this instead.
---
--- @param feature OpenSSLFeature Feature the binding must support
--- @return table|nil openssl The module if available and supporting the feature; nil otherwise
function openssl_wrapper.get_ungated(feature)
  local openssl = load_binding()
  if openssl == nil then
    return nil
  end
  return supports(openssl, feature) and openssl or nil
end

--- Explain why `get(feature)` is returning nil.
---
--- `get` collapses three different situations into one `nil`, and two of them
--- look identical to a caller while having opposite remedies: a host that
--- cannot accelerate is a fact to design around, whereas a host that has simply
--- not called `use(true)` yet is a one-line initialisation bug. The second is
--- the likely one on Control4, where `CRYPTO_USE_OPENSSL` is not set in the
--- DriverWorks environment, so a driver that forgets the call reads as "no
--- binding" for every feature on hardware that has four of them.
---
--- @param feature OpenSSLFeature? Feature to explain; omit to ask only about the flag and the binding
--- @return string|nil reason Human-readable cause, or nil when the feature is available
function openssl_wrapper.unavailable_reason(feature)
  if not _use_openssl then
    return "OpenSSL acceleration is not enabled: call crypto.use_openssl(true) during initialisation "
      .. "(CRYPTO_USE_OPENSSL is not set in every host environment, notably Control4 DriverWorks)"
  end
  local openssl = load_binding()
  if openssl == nil then
    return "the lua-openssl binding is not available on this host"
  end
  if feature ~= nil and not supports(openssl, feature) then
    return "the lua-openssl binding does not support " .. tostring(feature)
  end
  return nil
end

--- Report which features the currently loaded binding supports.
---
--- Intended for diagnostics. It reports what `get` would return, so every entry
--- is false while acceleration is off, regardless of what the host can do --
--- call `unavailable_reason` to tell that case apart from a binding that really
--- lacks the feature.
---
--- @return table<OpenSSLFeature, boolean> features Support map (empty when the binding is unavailable)
function openssl_wrapper.features()
  local report = {}
  for _, feature in pairs(OpenSSLFeature) do
    report[feature] = openssl_wrapper.get(feature) ~= nil
  end
  return report
end

-- ============================================================================
-- TESTS
-- ============================================================================

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
function openssl_wrapper.selftest()
  print("Running OpenSSL feature-gating test vectors...")

  -- Snapshot state so the test cannot disturb a real binding or a caller's flag.
  local saved_use = _use_openssl
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

return openssl_wrapper
