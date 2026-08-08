--- @module "crypto"
--- Portable cryptographic primitives for Lua with optional OpenSSL acceleration.
--- Pure-Lua implementations of hashing (SHA-256/512, BLAKE2), AEAD ciphers
--- (ChaCha20-Poly1305, AES-GCM), the Poly1305 MAC, HKDF key derivation,
--- Curve25519/448 Diffie-Hellman, Ed25519 signatures, and SRP-6a. Runs on Lua
--- 5.1, 5.2, 5.3, 5.4, and LuaJIT with zero C dependencies.
---
--- Key generation draws from `crypto.random`, which uses the host CSPRNG and
--- raises when there is not one. It never falls back to `math.random`.
---
--- When the host provides the lua-openssl binding (e.g. Control4 DriverWorks OS
--- >= 3.4.1), hashing and AEAD transparently prefer it for speed and fall back to
--- the pure-Lua implementations otherwise. The elliptic-curve Diffie-Hellman
--- functions (x25519/x448) and Ed25519 signing always use the portable
--- implementations regardless of the OpenSSL flag -- the shipped lua-openssl
--- builds cannot perform the raw Curve25519/448 operations, and cannot sign
--- with an Ed25519 key even when they can import one.
---
--- @usage
--- local crypto = require("crypto")
--- print(crypto.version())
---
--- -- opt-in OpenSSL acceleration; automatically falls back to pure Lua
--- crypto.use_openssl(true)
---
--- local digest = crypto.sha512.sha512_hex("hello")
--- local ct = crypto.chacha20_poly1305.encrypt(key, nonce, plaintext, aad)
--- local shared = crypto.x25519.diffie_hellman(my_private, their_public)
---
--- @class crypto
local crypto = {
  -- Hash functions
  --- @type crypto.sha256
  sha256 = require("crypto.sha256"),
  --- @type crypto.sha512
  sha512 = require("crypto.sha512"),
  --- @type crypto.blake2
  blake2 = require("crypto.blake2"),

  -- AEAD ciphers
  --- @type crypto.chacha20_poly1305
  chacha20_poly1305 = require("crypto.chacha20_poly1305"),
  --- @type crypto.aes_gcm
  aes_gcm = require("crypto.aes_gcm"),

  -- Stream ciphers
  --- @type crypto.chacha20
  chacha20 = require("crypto.chacha20"),

  -- MAC
  --- @type crypto.poly1305
  poly1305 = require("crypto.poly1305"),

  -- Key derivation
  --- @type crypto.hkdf
  hkdf = require("crypto.hkdf"),

  -- Cryptographically secure randomness (raises rather than returning weak bytes)
  --- @type crypto.random
  random = require("crypto.random"),

  -- Arbitrary-precision integers (OpenSSL-preferred modular exponentiation)
  --- @type crypto.bignum
  bignum = require("crypto.bignum"),

  -- Password-authenticated key exchange (client side)
  --- @type crypto.srp
  srp = require("crypto.srp"),

  -- Diffie-Hellman (always pure Lua)
  --- @type crypto.x25519
  x25519 = require("crypto.x25519"),
  --- @type crypto.x448
  x448 = require("crypto.x448"),

  -- Digital signatures (always pure Lua)
  --- @type crypto.ed25519
  ed25519 = require("crypto.ed25519"),

  -- Optional OpenSSL acceleration (exposed for diagnostics and feature queries)
  --- @type crypto.openssl_wrapper
  openssl_wrapper = require("crypto.openssl_wrapper"),
}

local openssl_wrapper = crypto.openssl_wrapper

--- Library version (injected at build time for releases).
local VERSION = "dev"

--- Enable or disable OpenSSL acceleration for the primitives that support it
--- (hashing and AEAD). Opt-in and safe: when the lua-openssl binding is
--- unavailable, or a given primitive is not accelerated, the pure-Lua
--- implementation is used automatically. Curve25519/448 always use pure Lua.
--- @param use boolean
function crypto.use_openssl(use)
  openssl_wrapper.use(use)
end

--- Get the library version string.
--- @return string version Version string (e.g., "v1.0.0" or "dev")
function crypto.version()
  return VERSION
end

--- Run every module's known-answer self-test.
--- @return boolean ok True if all module self-tests pass
function crypto.selftest()
  local modules = {
    "sha256",
    "sha512",
    "blake2",
    "chacha20",
    "chacha20_poly1305",
    "poly1305",
    "aes_gcm",
    "hkdf",
    "random",
    "bignum",
    "srp",
    "x25519",
    "x448",
    "ed25519",
    "openssl_wrapper",
  }
  local ok = true
  for _, name in ipairs(modules) do
    local mod = crypto[name]
    if type(mod.selftest) == "function" then
      if mod.selftest() == false then
        ok = false
      end
    end
  end
  return ok
end

return crypto
