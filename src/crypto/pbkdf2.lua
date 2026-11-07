--- @module "crypto.pbkdf2"
--- PBKDF2, RFC 8018 section 5.2, over HMAC-SHA256 or HMAC-SHA512.
---
--- A thin layer over the HMAC functions in `crypto.sha256` / `crypto.sha512`,
--- which already run through OpenSSL when acceleration is enabled, so PBKDF2
--- inherits that acceleration without a route of its own, as HKDF does.
---
--- The cost is one HMAC per iteration per output block (32 bytes for SHA-256,
--- 64 for SHA-512). In pure Lua an HMAC-SHA256 takes about 0.01 ms under LuaJIT
--- and 0.6 to 4 ms under PUC Lua 5.1 to 5.5 on a desktop, so a high iteration
--- count is only practical with the JIT or with acceleration on.
---
--- @usage
--- local pbkdf2 = require("crypto.pbkdf2")
--- local key = pbkdf2.derive("sha256", password, salt, 10000, 32)
---
--- @class crypto.pbkdf2
local pbkdf2 = {}

local bit32 = require("bitn").bit32

local sha256 = require("crypto.sha256")
local sha512 = require("crypto.sha512")
local utils = require("crypto.utils")
local bytes = utils.bytes

-- Local references for performance
local bit32_raw_bxor = bit32.raw_bxor
local ceil = math.ceil
local string_byte = string.byte
local string_char = string.char
local string_sub = string.sub
local table_concat = table.concat

--- A PRF PBKDF2 can use: HMAC over one hash, and that hash's output length.
--- @class Pbkdf2Hash
--- @field hmac fun(key: string, data: string): string HMAC over this hash
--- @field length integer hLen in bytes

--- @type table<string, Pbkdf2Hash>
local HASHES = {
  sha256 = { hmac = sha256.hmac_sha256, length = 32 },
  sha512 = { hmac = sha512.hmac_sha512, length = 64 },
}

--- Derive a key with PBKDF2-HMAC.
---
--- @param hash_name string "sha256" or "sha512"
--- @param password string Password P, any bytes
--- @param salt string Salt S, any bytes
--- @param iterations integer Iteration count c, at least 1
--- @param length integer Derived key length dkLen in bytes, at least 1
--- @return string key `length` bytes
function pbkdf2.derive(hash_name, password, salt, iterations, length)
  local params = HASHES[hash_name]
  if params == nil then
    error("PBKDF2: unsupported hash " .. tostring(hash_name) .. ' (expected "sha256" or "sha512")', 2)
  end
  assert(type(password) == "string", "PBKDF2: password must be a string")
  assert(type(salt) == "string", "PBKDF2: salt must be a string")
  assert(
    type(iterations) == "number" and iterations >= 1 and iterations % 1 == 0,
    "PBKDF2: iterations must be a positive integer"
  )
  assert(type(length) == "number" and length >= 1 and length % 1 == 0, "PBKDF2: length must be a positive integer")

  local hmac = params.hmac
  local hash_length = params.length
  local block_count = ceil(length / hash_length)
  -- RFC 8018 5.2 step 1: the block index is a 32-bit counter.
  assert(block_count <= 4294967295, "PBKDF2: derived key too long")

  local blocks = {}
  for i = 1, block_count do
    -- T_i = U_1 xor U_2 xor ... xor U_c, with U_1 = PRF(P, S || INT(i)).
    local u = hmac(password, salt .. bytes.u32_to_be_bytes(i))
    local t = { string_byte(u, 1, hash_length) }
    for _ = 2, iterations do
      u = hmac(password, u)
      for j = 1, hash_length do
        t[j] = bit32_raw_bxor(t[j], string_byte(u, j))
      end
    end
    local chars = {}
    for j = 1, hash_length do
      chars[j] = string_char(t[j])
    end
    blocks[i] = table_concat(chars)
  end
  return string_sub(table_concat(blocks), 1, length)
end

return pbkdf2
