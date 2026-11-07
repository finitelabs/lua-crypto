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

return hkdf
