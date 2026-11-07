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
--- - AES-CCM's block cipher (raw AES-ECB)
--- - ChaCha20 stream cipher
--- - Big-number arithmetic (SRP)
--- - P-256 field arithmetic
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

--- FIPS-197 Appendix C known answers for the ECB probe: one plaintext block and,
--- per key size, the C.1 (AES-128), C.2 (AES-192) and C.3 (AES-256) key and
--- ciphertext, all as hex.
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

--- Decode hex to bytes. The wrapper requires nothing from the library, so it
--- carries its own rather than pulling in `crypto.utils`.
--- @param hex string Hex digits
--- @return string bytes
local function from_hex(hex)
  return (hex:gsub("..", function(cc)
    return string.char(tonumber(cc, 16))
  end))
end

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
  [OpenSSLFeature.ECB] = {
    min_version = "0.8.0",
    probe = function(openssl)
      local cipher_lib = openssl.cipher
      if type(cipher_lib) ~= "table" or type(cipher_lib.get) ~= "function" then
        return false
      end
      -- Measured on a Control4 controller (2026-11-03, lua-openssl 0.8.5):
      -- cipher.get("aes-128-ecb"):encrypt(block, key, nil, false) returns the
      -- raw block. Two blocks go in one call, so the answer also proves padding
      -- is off and that a batch comes back block for block.
      local plaintext = from_hex(ECB_PLAINTEXT_HEX)
      for _, answer in ipairs(ECB_KNOWN_ANSWERS) do
        local cipher = cipher_lib.get(answer.cipher)
        if cipher == nil then
          return false
        end
        local expected = from_hex(answer.ciphertext)
        if cipher:encrypt(plaintext .. plaintext, from_hex(answer.key), nil, false) ~= expected .. expected then
          return false
        end
      end
      return true
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

--- Whether acceleration is requested, as last set by `use`. Snapshot it before toggling the flag temporarily.
--- @return boolean enabled
function openssl_wrapper.enabled()
  -- Truthy like `get`, not `== true`, or restoring this answer could switch acceleration off.
  return _use_openssl and true or false
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

-- Private functions and values the tests in test/ check directly.
openssl_wrapper._internal = {
  from_hex = from_hex,
  FeatureRequirements = FeatureRequirements,
}

return openssl_wrapper
