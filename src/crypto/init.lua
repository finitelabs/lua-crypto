--- @module "crypto"
--- Portable cryptographic primitives for Lua with optional OpenSSL acceleration.
--- Pure-Lua implementations of hashing (SHA-256/512, BLAKE2), AEAD ciphers
--- (ChaCha20-Poly1305, AES-GCM), the Poly1305 MAC, and Curve25519/448
--- Diffie-Hellman. Runs on Lua 5.1, 5.2, 5.3, 5.4, and LuaJIT with zero C
--- dependencies.
---
--- When the host provides the lua-openssl binding (e.g. Control4 DriverWorks OS
--- >= 3.4.1), hashing and AEAD transparently prefer it for speed and fall back to
--- the pure-Lua implementations otherwise. The elliptic-curve Diffie-Hellman
--- functions (x25519/x448) always use the portable implementations regardless of
--- the OpenSSL flag -- the shipped lua-openssl builds cannot perform the raw
--- Curve25519/448 operations.
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

  -- Diffie-Hellman (always pure Lua)
  --- @type crypto.x25519
  x25519 = require("crypto.x25519"),
  --- @type crypto.x448
  x448 = require("crypto.x448"),
}

local openssl_wrapper = require("crypto.openssl_wrapper")

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
    "x25519",
    "x448",
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
