--- @module "crypto.srp"
--- SRP-6a **client**, parameterised by group and hash (RFC 5054 / RFC 2945).
---
--- This module implements the *client* half of SRP-6a and nothing else. It
--- derives the client public value `A`, the premaster secret `S`, the session
--- key `K` and the client proof `M1`, and it verifies the server proof `M2`.
--- There is deliberately no server side: nothing here derives `B` from a
--- verifier, and nothing validates a client proof. Do not assume `crypto.srp`
--- can stand in for an SRP server.
---
--- The default parameter set is `srp.GROUP_3072` -- RFC 5054 Appendix A group 15
--- (the 3072-bit MODP safe prime, g = 5) with SHA-512. That is the parameter set
--- HomeKit Accessory Protocol Pair-Setup uses, with `I = "Pair-Setup"` and `P`
--- the setup code shown on the accessory.
---
--- Encoding conventions
--- --------------------
--- The conventions below follow `srptools`, the library pyatv drives for HAP
--- Pair-Setup, so they interoperate with a real accessory. They are *not* a
--- naive reading of RFC 5054, and every one of them is load-bearing:
---
--- * `PAD(x)` is big-endian, left-zero-padded to the byte length of `N`
---   (384 bytes for group 15). It is applied in exactly two places:
---   `k = H(N | PAD(g))` and `u = H(PAD(A) | PAD(B))`.
--- * Everywhere else an integer is hashed in **minimal** big-endian form, with
---   leading zero bytes stripped -- notably `N`, `g`, `A` and `B` inside `M1`,
---   and `S` inside `K`.
--- * The salt is hashed as the **raw bytes the server supplied**, never
---   re-encoded through an integer. A salt whose leading byte is zero keeps that
---   byte. Routing it through an integer silently shortens it by one byte and
---   produces a ~1-in-256 intermittent pairing failure rather than an obvious
---   break, so the third known-answer vector pins this specifically.
---
--- @usage
--- local srp = require("crypto.srp")
---
--- local session = srp.new({ username = "Pair-Setup", password = setup_code })
--- send(session:get_public()) --  A, 384 bytes
--- session:process(salt, B) --     the server's s (raw bytes) and B
--- send(session:get_proof()) --    M1, 64 bytes
--- assert(session:verify(server_M2), "server proof rejected")
--- local key = session:get_session_key() -- K, 64 bytes
---
--- @class crypto.srp
local srp = {}

local bignum = require("crypto.bignum")
local random = require("crypto.random")
local sha256 = require("crypto.sha256")
local sha512 = require("crypto.sha512")

local utils = require("crypto.utils")
local bytes = utils.bytes

local table_concat = table.concat

-- ============================================================================
-- GROUPS AND HASHES
-- ============================================================================

--- RFC 5054 Appendix A / RFC 3526 group 15: the 3072-bit MODP safe prime.
local RFC5054_3072_N_HEX = table_concat({
  "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74",
  "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437",
  "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed",
  "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05",
  "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb",
  "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b",
  "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718",
  "3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33",
  "a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7",
  "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864",
  "d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2",
  "08e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff",
})

--- An SRP group: the safe prime `N` as a hex string, the generator `g`, and the
--- hash `srp.new` defaults to when the caller does not name one.
--- @alias SrpGroup { name: string, N: string, g: integer|string, hash: string }

--- RFC 5054 group 15 (3072-bit) with g = 5 and SHA-512 -- the HAP Pair-Setup
--- parameter set, and the default for `srp.new`.
--- @type SrpGroup
srp.GROUP_3072 = {
  name = "RFC 5054 group 15 (3072-bit)",
  N = RFC5054_3072_N_HEX,
  g = 5,
  hash = "sha512",
}

--- A hash usable as SRP's `H`: a name for diagnostics and a function taking a
--- byte string to a raw digest.
--- @alias SrpHash { name: string, hash: fun(data: string): string }

--- Hashes `srp.new` accepts by name.
--- @type table<string, SrpHash>
local HASHES = {
  sha256 = { name = "sha256", hash = sha256.sha256 },
  sha512 = { name = "sha512", hash = sha512.sha512 },
}

--- Bytes of client private exponent `a` generated when the caller does not
--- supply one. RFC 5054 section 3.1 requires at least 256 bits.
local PRIVATE_BYTES = 32

-- ============================================================================
-- INTERNAL HELPERS
-- ============================================================================

--- Parsed form of a group, memoized so the 3072-bit prime is decoded once.
--- Keyed weakly on the group table itself, so a caller-supplied group does not
--- pin its parsed form forever.
--- @type table<SrpGroup, table>
local group_cache = setmetatable({}, { __mode = "k" })

--- Decode a group into the values every session needs.
---
--- `N_min` / `g_min` are the minimal big-endian encodings used inside `M1`, and
--- `g_pad` is `PAD(g)` as used inside `k`; both forms are precomputed because
--- the difference between them is exactly the convention this module has to get
--- right.
---
--- @param group SrpGroup Group description
--- @return table params Fields: N, g, n_bytes, N_min, g_min, g_pad, derived
local function resolve_group(group)
  assert(type(group) == "table", "SRP: group must be a table")
  local params = group_cache[group]
  if params then
    return params
  end

  assert(type(group.N) == "string", "SRP: group.N must be a hex string")
  local N = bignum.from_hex(group.N)
  assert(not bignum.is_zero(N), "SRP: group modulus N must be non-zero")

  -- Read into a local because narrowing applies to locals, not table fields:
  -- `type(group.g)` does not tell the checker anything about `group.g`.
  local g_spec = group.g
  local g
  if type(g_spec) == "number" then
    g = bignum.from_number(g_spec)
  else
    assert(type(g_spec) == "string", "SRP: group.g must be a number or a hex string")
    g = bignum.from_hex(g_spec)
  end
  assert(not bignum.is_zero(g), "SRP: group generator g must be non-zero")

  local n_bytes = bignum.byte_length(N)
  params = {
    N = N,
    g = g,
    n_bytes = n_bytes,
    N_min = bignum.to_bytes(N),
    g_min = bignum.to_bytes(g),
    g_pad = bignum.to_bytes(g, n_bytes),
    -- Per-hash constants, keyed weakly on the hash table.
    derived = setmetatable({}, { __mode = "k" }),
  }
  group_cache[group] = params
  return params
end

--- Compute the group/hash constants that do not depend on the session.
---
--- `k = H(N | PAD(g))` is the SRP-6a multiplier; `hn_xor_hg = H(N) XOR H(g)` is
--- the first term of `M1`. Note the asymmetry that trips people up: `g` is
--- padded inside `k` but minimal inside `H(g)`.
---
--- @param params table Parsed group from `resolve_group`
--- @param hash SrpHash Hash in use
--- @return table constants Fields: k (BigNum), hn_xor_hg (string)
local function derive_constants(params, hash)
  local constants = params.derived[hash]
  if constants then
    return constants
  end
  local h = hash.hash
  constants = {
    k = bignum.from_bytes(h(params.N_min .. params.g_pad)),
    hn_xor_hg = bytes.xor_bytes(h(params.N_min), h(params.g_min)),
  }
  params.derived[hash] = constants
  return constants
end

--- Resolve `opts.hash` to a hash table.
--- @param spec string|SrpHash Registered name, or a custom `{ name, hash }`
--- @return SrpHash hash
local function resolve_hash(spec)
  if type(spec) == "table" then
    assert(type(spec.name) == "string", "SRP: custom hash needs a string 'name'")
    assert(type(spec.hash) == "function", "SRP: custom hash needs a function 'hash'")
    return spec
  end
  local entry = HASHES[spec]
  assert(entry, "SRP: unsupported hash '" .. tostring(spec) .. "'")
  return entry
end

-- ============================================================================
-- SESSION
-- ============================================================================

--- One client-side SRP-6a exchange.
---
--- Derived values are kept as fields so a failing exchange can be localised to a
--- single step: `k`, `x`, `v`, `u` and `S` are BigNums, `K`, `M1` and `M2` are
--- raw digests. Treat them as read-only; the accessors below are the supported
--- interface.
---
--- @class crypto.srp.Session
--- @field group SrpGroup Group in use
--- @field params table Parsed group from `resolve_group`
--- @field hash SrpHash Hash in use
--- @field username string Identity `I`
--- @field password string Password `P`
local Session = {}
Session.__index = Session

--- Set the client private exponent `a` explicitly.
---
--- Only needed for deterministic tests and for protocols that derive `a` from
--- existing key material; otherwise `get_public()` generates one. Discards any
--- previously computed `A`.
---
--- @param a string Private exponent as big-endian bytes
--- @return crypto.srp.Session self For chaining
function Session:set_private(a)
  assert(type(a) == "string" and #a > 0, "SRP: private exponent must be a non-empty byte string")
  local value = bignum.from_bytes(a)
  assert(not bignum.is_zero(bignum.mod(value, self.params.N)), "SRP: private exponent must not be 0 mod N")
  self.a = value
  self.A = nil
  self.A_bytes = nil
  return self
end

--- Client public value `A = g^a mod N`.
---
--- Generates a random `a` on first call if `set_private` was not used, then
--- caches `A` for the life of the session.
---
--- @return string A Big-endian bytes, left-padded to the byte length of N
function Session:get_public()
  if not self.A_bytes then
    if not self.a then
      -- `crypto.random` raises when the host has no CSPRNG rather than handing
      -- back a guessable `a`: recovering `a` recovers `S`, therefore `K`,
      -- therefore the session, and permits an offline attack on the setup code.
      self:set_private(random.bytes(PRIVATE_BYTES))
    end
    local params = self.params
    local A = bignum.mod_exp(params.g, self.a, params.N)
    assert(not bignum.is_zero(A), "SRP: computed client public value A is zero mod N")
    self.A = A
    self.A_bytes = bignum.to_bytes(A, params.n_bytes)
  end
  return self.A_bytes
end

--- Process the server's salt and public value, deriving the whole exchange.
---
--- Computes `x`, `v`, `u`, `S`, `K`, `M1` and `M2`. Aborts -- as RFC 5054
--- section 2.5.4 requires -- if `B mod N == 0` or if `u == 0`, either of which
--- would let a malicious server fix the premaster secret.
---
--- `salt` is used byte for byte, exactly as received. It is not an integer and
--- must not be normalised into one.
---
--- @param salt string Server salt `s`, raw bytes
--- @param B string Server public value `B`, big-endian bytes
--- @return crypto.srp.Session self For chaining
function Session:process(salt, B)
  assert(type(salt) == "string", "SRP: salt must be a byte string")
  assert(type(B) == "string" and #B > 0, "SRP: server public value B must be a non-empty byte string")

  local params = self.params
  local N = params.N
  local h = self.hash.hash

  -- B is kept exactly as supplied for hashing; only the safety check reduces it.
  local B_value = bignum.from_bytes(B)
  if bignum.is_zero(bignum.mod(B_value, N)) then
    error("SRP: server public value B is 0 mod N; aborting per RFC 5054", 2)
  end

  local A_bytes = self:get_public()
  local A_value = self.A

  -- u = H(PAD(A) | PAD(B)). Checked before the expensive exponentiations so a
  -- degenerate server is rejected without doing the work.
  local u = bignum.from_bytes(h(A_bytes .. bignum.to_bytes(B_value, params.n_bytes)))
  if bignum.is_zero(u) then
    error("SRP: scrambling parameter u is 0; aborting per RFC 5054", 2)
  end

  local constants = derive_constants(params, self.hash)
  local k = constants.k

  -- x = H(s | H(I | ":" | P)). `salt` goes in raw: a leading zero byte is part
  -- of the salt, not padding to be stripped.
  local x = bignum.from_bytes(h(salt .. h(self.username .. ":" .. self.password)))

  -- v = g^x mod N, then S = (B - k*v)^(a + u*x) mod N. The subtraction can go
  -- negative, so it goes through mod_sub to land on a non-negative residue.
  local v = bignum.mod_exp(params.g, x, N)
  local base = bignum.mod_sub(B_value, bignum.mod_mul(k, v, N), N)
  local S = bignum.mod_exp(base, bignum.add(self.a, bignum.mul(u, x)), N)

  -- K, M1 and M2 all take S, A and B in minimal form, and the salt raw.
  local K = h(bignum.to_bytes(S))
  local A_min = bignum.to_bytes(A_value)
  local M1 = h(table_concat({
    constants.hn_xor_hg,
    h(self.username),
    salt,
    A_min,
    bignum.to_bytes(B_value),
    K,
  }))
  local M2 = h(A_min .. M1 .. K)

  self.salt, self.B = salt, B_value
  self.k, self.x, self.v, self.u, self.S = k, x, v, u, S
  self.K, self.M1, self.M2 = K, M1, M2
  return self
end

--- Client proof `M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)`.
--- @return string M1 Raw digest (64 bytes for SHA-512)
function Session:get_proof()
  assert(self.M1, "SRP: call process(salt, B) before get_proof()")
  return self.M1
end

--- Verify the server proof `M2 = H(A | M1 | K)`.
---
--- The comparison is constant time, so a wrong proof leaks no information about
--- how much of it was right.
---
--- @param M2 string Server proof, raw digest
--- @return boolean valid True when the proof matches
function Session:verify(M2)
  assert(self.M2, "SRP: call process(salt, B) before verify()")
  if type(M2) ~= "string" then
    return false
  end
  return bytes.constant_time_compare(self.M2, M2)
end

--- Shared session key `K = H(S)`.
--- @return string K Raw digest (64 bytes for SHA-512)
function Session:get_session_key()
  assert(self.K, "SRP: call process(salt, B) before get_session_key()")
  return self.K
end

-- ============================================================================
-- SRP PUBLIC INTERFACE
-- ============================================================================

--- Create a client session.
---
--- @param opts { group?: SrpGroup, hash?: string|SrpHash, username: string, password: string }
---   `group` defaults to `srp.GROUP_3072`; `hash` defaults to the group's own
---   hash name and may be `"sha256"`, `"sha512"`, or a custom `{ name, hash }`.
---   `username` is `I` (`"Pair-Setup"` for HAP) and `password` is `P`.
--- @return crypto.srp.Session session
function srp.new(opts)
  assert(type(opts) == "table", "SRP: srp.new requires an options table")
  assert(type(opts.username) == "string", "SRP: username (I) must be a string")
  assert(type(opts.password) == "string", "SRP: password (P) must be a string")

  local group = opts.group or srp.GROUP_3072
  local params = resolve_group(group)
  local hash = resolve_hash(opts.hash or group.hash or "sha512")

  return setmetatable({
    group = group,
    params = params,
    hash = hash,
    username = opts.username,
    password = opts.password,
  }, Session)
end

--- Whether an exchange will run at usable speed on this host.
---
--- SRP-6a's cost is dominated by modular exponentiation. On a Control4
--- controller (2026-10-18) a client exchange takes about 2.5 s in pure Lua with
--- LuaJIT's JIT on, about 28 s without it, and about 0.04 s through `bn.powmod`.
--- Lua there is effectively serialised across drivers, so the pure path stalls
--- them all for that long.
---
--- This is deliberately advisory. `crypto.bignum` stays portable and will
--- compute the same answer either way, because the pure path is what makes the
--- test suite runnable everywhere. But a HAP driver should check this before
--- starting Pair-Setup rather than discovering it by hanging, and it should not
--- have to reach through `openssl_wrapper.features()` into another module's
--- internals to do so.
---
--- The second return value says *why* an exchange would be slow, which matters
--- because "this host has no usable binding" and "nobody called
--- `crypto.use_openssl(true)`" are the same `false` and have nothing else in
--- common. Fail closed on the boolean; log the reason.
---
--- @return boolean accelerated True if modular exponentiation uses OpenSSL
--- @return string|nil reason Why it does not, when it does not
function srp.is_accelerated()
  return bignum.is_accelerated()
end

-- Private functions and values the tests in test/ check directly.
srp._internal = {
  resolve_group = resolve_group,
}

return srp
