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
local benchmark_op = utils.benchmark.benchmark_op

-- Local references for performance
local string_char = string.char
local string_rep = string.rep
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

  local g
  if type(group.g) == "number" then
    g = bignum.from_number(group.g)
  else
    assert(type(group.g) == "string", "SRP: group.g must be a number or a hex string")
    g = bignum.from_hex(group.g)
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
--- SRP-6a's cost is dominated by modular exponentiation over the group modulus,
--- and for the 3072-bit HAP group the gap between backends is not a matter of
--- taste. Measured on a Control4 controller (2026-08-07): `bn.powmod` takes
--- 5.08 ms, while the pure-Lua path extrapolates to roughly 176 s for the
--- 256-bit client exponent -- a factor of about 34,000. Worse, Lua execution is
--- effectively serialised across drivers there, so an unaccelerated exchange
--- does not merely run slowly, it blocks the controller until the watchdog
--- resets the driver.
---
--- This is deliberately advisory. `crypto.bignum` stays portable and will
--- compute the same answer either way, because the pure path is what makes the
--- test suite runnable everywhere. But a HAP driver should check this before
--- starting Pair-Setup rather than discovering it by hanging, and it should not
--- have to reach through `openssl_wrapper.features()` into another module's
--- internals to do so.
---
--- @return boolean accelerated True if modular exponentiation uses OpenSSL
function srp.is_accelerated()
  return bignum.is_accelerated()
end

-- ============================================================================
-- TEST VECTORS AND VALIDATION
-- ============================================================================

-- Generated by tools/generate_srp_vectors.py -- do not edit by hand.
-- Source of truth: srptools, the library pyatv drives for HAP Pair-Setup.
local srp_vectors = {
  {
    name = "HAP Pair-Setup, 8-digit PIN",
    password = "123-45-678",
    salt = "beb25379d1a8581eb5a727673a2441ee",
    a = "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
    b = "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
    k = "a9c2e2559bf0ebb53f0cbbf62282906bede7f2182f00678211fbd5bde5b28503"
      .. "3a4993503b87397f9be5ec02080fedbc0835587ad039060879b8621e8c3659e0",
    x = "f63012102e042051ad49d9598ddd7d1f7f05b9306fb5c4011eb2f9410f36d036"
      .. "9ffad9c644fdf308fcb7c09bf56dc2c0bb9e4e942f574e0786386a124f2bcde4",
    v = "cfe3853f15657e2ee3638ffb7a7743c76cc1f85c0d7fcf2db85172c77800eda2"
      .. "19e0e4fa98c95cb7634d4a35e8c74d6f728cf3864990c4e93c32f5120d71da56"
      .. "ecf3711a02e9e0727cef62920e815306cc4c4375a40991b9e074a69fbf06986b"
      .. "49c92edcda1e9a35ed4ef0b7d4351c1cc8c87844c560e1942e24438e50b04cbb"
      .. "888674500e792449173598045dd1cba0c2128b2661f03d4417b29b4426a732b9"
      .. "ce929abc431f561241633e095cc3b03976ed2bdc39ca2fd5265dade7cd04dd84"
      .. "122278f190edc86c6ae9e1cedc03ec6d97218b7d587d47286678d305a5168c07"
      .. "873d79ac72a42fe39235791a0f2841c68b2a89f5acb512a799e5842dca9eeaa3"
      .. "b21e9ff5072e94aecb8f3572a540a65e577407bf0bed9a1b32f32c7161f675b4"
      .. "a2e29353fac3463989f45522e6c0903154fbc51ba29079af6f7330ad596ea4b9"
      .. "5b3533e3c2f78fec6cb3946e9e7d5dabb67d5605ea517eea2c2fc18552b80e3f"
      .. "7b97168d2a9eb635205c534c46ecc51a052a4ff8ae5eb199129720e8c0ffaedd",
    A = "fab6f5d2615d1e323512e7991cc37443f487da604ca8c9230fcb04e541dce628"
      .. "0b27ca4680b0374f179dc3bdc7553fe62459798c701ad864a91390a28c93b644"
      .. "adbf9c00745b942b79f9012a21b9b78782319d83a1f8362866fbd6f46bfc0ddb"
      .. "2e1ab6e4b45a9906b82e37f05d6f97f6a3eb6e182079759c4f6847837b62321a"
      .. "c1b4fa68641fcb4bb98dd697a0c73641385f4bab25b793584cc39fc8d48d4bd8"
      .. "67a9a3c10f8ea12170268e34fe3bbe6ff89998d60da2f3e4283cbec1393d52af"
      .. "724a57230c604e9fbce583d7613e6bffd67596ad121a8707eec4694495703368"
      .. "6a155f644d5c5863b48f61bdbf19a53eab6dad0a186b8c152e5f5d8cad4b0ef8"
      .. "aa4ea5008834c3cd342e5e0f167ad04592cd8bd279639398ef9e114dfaaab919"
      .. "e14e850989224ddd98576d79385d2210902e9f9b1f2d86cfa47ee244635465f7"
      .. "1058421a0184be51dd10cc9d079e6f1604e7aa9b7cf7883c7d4ce12b06ebe160"
      .. "81e23f27a231d18432d7d1bb55c28ae21ffcf005f57528d15a88881bb3bbb7fe",
    B = "f10ea26e7f6729cf4ad84ee29797902444db19e43a4208f0228db31dbcebf1ce"
      .. "2599dd34db5527b459959d03def823ca34b26acebdcda6e5be266bda03434f41"
      .. "99709b44f9006319c8c9954440cfa8513a3efaf891ffe7e9a22d114a627ff876"
      .. "a169f8475f2338342ec9a22916ff13949848d2653bfbad782b99e2f0dbe5a6c5"
      .. "e698a3b895a426dc357c6986001b9023b0eb05a13c3b9ec04ee837ddfc12eef3"
      .. "536dab67ec1c47881eb87bbfbe7f010823d051d33e15c6e9138780395d4ecf10"
      .. "bf610e11a5b0e3ee8d122665feba6b17c9eba084a60d15aae69152b827b507ed"
      .. "e6d824237d8596a51e6355faf8727d5e67f91e60ac85feebdb852eeb61c9e6d1"
      .. "7a48d55d6bc815adfe03daec5b6bd8a3d28b8fe4bc78e452c2cd8aa89fedaf39"
      .. "252f4cb354c595c09fa2251078746482fba13daf27e156aabd18800efd97e472"
      .. "9b74217bc9611d54250422b00c0ade7bf0721c5f1b7d479c3c32d6d34b29d2fb"
      .. "e158ebe5ad9e9e40d997f755e919c77ad5be10300d55bbe921aee598d4dbfff3",
    u = "d4af9d1fde81c67160f53a86495e58016c71109e769944d65a07835170e52b7a"
      .. "579e8273e1cfa374537535e74d617c530f403914049da1757c50e7361d078fe4",
    S = "309ce4265954b7f9005a7e137eca9173e313c349445b54f36e38668a66ec011a"
      .. "1ca015e8fc24e16b0d87d95b8083d8fd722acb81c1a96ae87e0b80d1789d6670"
      .. "5a41f90286c852a73e139a5dc628be44d4f7b4c76e6506af49b22ec2fedaaec8"
      .. "5c518a71e7867db978997234ade66b5beb0aaa1259409778f7b461fcc0d1a288"
      .. "4ffa4fbb1084b733be16f1a6ed890269541df5356cf871e38c3c6fc93edd1952"
      .. "efb89e6b92c0452f8766648f3b48337dd32b39bf20a64632719de457910760cd"
      .. "81188beac6176e24555952ec3d3d84cfcc320f25381b525269e263528838f5a7"
      .. "a62c85d350f1c28856e90eaf9907f8471b8ce5b7c251472c7302ca8bd04e1741"
      .. "2b24d6c3d70e4a16caeb65df5d33ec0d4e06869d99c690d872a8693d273c8f92"
      .. "c4789adc376844d4d0621f0dc38f9c550e7312c8f9da78ef20ddcf5954133e83"
      .. "f76ddacf8a5ece59b2b61770ded05418fc37af37ca29a423848b16d929335a4f"
      .. "7cae9025f2bdf4a368fc6e510eec39a34dc15665ebee4b504cb55f47edb48a5c",
    K = "8d81d9699f88f80724b5ccea8af575afb9ec0e32a6986336a58e7697f8394b54"
      .. "1751f886a362c05e86cac223a522218b4c704635accacbff498b5a17e6baa3be",
    M1 = "5405c5ad299a761d8afe17c45383de84a46f6c0d437a29bd9476bf4b77dd79e7"
      .. "b95674a966498a3c5f98bf8c933f4baba9555765fc1ecc240eaeda3363a68d42",
    M2 = "65623be9ae14a44abcee4951655103a51913c84dbd90eda6c386819bfe7d2b0d"
      .. "7603ce198b4c0b257dfec327bcf035cc0dacd7e47b79c585aec992af0490c61b",
  },
  {
    name = "HAP Pair-Setup, 4-digit PIN",
    password = "3939",
    salt = "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
    a = "1d1e2f3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6",
    b = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0",
    k = "a9c2e2559bf0ebb53f0cbbf62282906bede7f2182f00678211fbd5bde5b28503"
      .. "3a4993503b87397f9be5ec02080fedbc0835587ad039060879b8621e8c3659e0",
    x = "956dcab6654323ea59d60692c2b5c1b7737a6f488e8e9808a8d636109668d014"
      .. "3dc0954764ead68763ba2fdeb26fe313ecdad98c46a06e36436d2d2f01f8283a",
    v = "1db374f7d5d9572ef2ca480f2486d045d3f892de338e80e733e83ea6e18bdc82"
      .. "ce0d40a69076c2ee273d2b365fd1296dc0db4826dfc010c5c608ab0ef399fcd3"
      .. "46f594dbc9eda52e8107c307a80d7f23a78345bb036684c911ee4cbacef0bd54"
      .. "ba91aeb6c039d5946e407b1df89a0c456abcc4d3cdc69b5705d2af5a177094de"
      .. "5943a28ad127fd00acfbb064df86c41a542d8455527784e1b3dcbaae41f2fab7"
      .. "9fc1083ec1d13f8aeebe3cf3532e47a577d7bfcad7fac05507df97aed5f0c6ef"
      .. "4bfb185999842ed5d191b0296608cd5e06355bf7b797264097c7c587ab844e56"
      .. "359a4895ed99fb8df2b00d6a857ca12cbdf554d41f3316275ba3fe485b2b4fa3"
      .. "857ced98c0e522193726c262963dc1ad85720e42c23f9a01d749a86664b4f47a"
      .. "74f6193cfd27a84d7a8baa4e0b8fb28caab6cd19fbaa38c5be54d6007787dab7"
      .. "156286019c50e6f8b1e6b6fc4b9fdb3992242de199c231549bfbe8e6311bd304"
      .. "34bd63e384bb58b648e83a5a05d0234176f344f3001ee1a8cba127aea976a0e9",
    A = "de7460f6ad6438e8c91615e668456cf0a88911cc16ab77fffca2335788499a85"
      .. "4bec07ebeb3a352caa79bf815776ff5ac3ef69d7504f8854de94484c1bc8f21f"
      .. "713a51e6ea856e8d0b402a8986fb049e0f66d2fa420fbc38cd4e7b8dd52d3839"
      .. "f116b188443e078f803e06502b34818437ce8acaaae810c47017d22158f2dcc5"
      .. "4b926935b2360f9b15d9c50fc65933f189cb3081d6dfba978716fa0f1d0188bc"
      .. "a82c41241c05141537128c28f8e17e37422116e410689562fc0132908d9ecbba"
      .. "a7ce637528802009545c8cb39734c5cd43047b5be7239d286df9a0c68dc36f76"
      .. "002eeb683fc207880301612d2da0070a195c6bc1959f52a08ac3519a528f0696"
      .. "f1335b8e487029460e607f390af361d9861b3abff460785cd484380ef87d369d"
      .. "3ff7461796e4384ff0a711bfe1227da33d6ad7a763a2f24915be0dfb2827c9cf"
      .. "9cfcde20fbff65c2fbba2c56d1e652e9172db8bd9825279d12ff51147af67e93"
      .. "112e5073d949f372d285298851eaceec9f442081bd0615810ba70af20df15092",
    B = "c462c3ab34762e9c723360c1a78d30016ac79a679cd8adc997111a842ce6a99a"
      .. "7ff316a558e8f4a1b2d94633a620a84000788081ea7867c8c3a18e12e96d4e1a"
      .. "142b18beee958e3c2e5da7bd927a4d4859b12c666d0d941dd183a0b6401bc567"
      .. "0fec8ec9fb9c9534e8c34880b5f05ae962b12fd903a3af0ef3f7dfd6be81f385"
      .. "8f81be60afffcfae6b6a8b73462cca451bcb64e8fda884109cefe22a3d711176"
      .. "d327fdf03352106fb11c3220c5715810ba1a45f67f4b6649e2cf6a7172b4257a"
      .. "6728e5423cba18a371b376c0aed3b9a930c206f47e7110d67eb8b707b300d1cd"
      .. "d9731fa14ce48b26f07261598c1501ba06610faa8f25bfd0dc9f657e90ee2310"
      .. "2a04b2304f45ececbf1470e24fb46067decb99c0bbd31b53c7fed135a301ae5b"
      .. "fa858601f0f1c23524ecae5fb50385fc72467b4dc95ace632cc7d4bd6be81f5b"
      .. "d68db69da4264daa10394b39c822360d97894682b34718dcb4c26779eacb696b"
      .. "2b8b7d50c9139e2bdaf2a5ce0b8cee5e8e28cb2ad3e64e824086cc87f02ce6f7",
    u = "76ac3f8010b3121c47cd1b8658e63357c624572489c4926348e5484d88c461d1"
      .. "6862858e97ea1ea53b4e6e372fbaccb1e6b1907bae0267085d7f3c0015137dae",
    S = "30c4b3ab83046ffab2b95f0038d75d76d754f1937be01fb437cca89b9714174a"
      .. "d2d800427c221774afab641f0708658a86fb28ad4df01aa57c558d64fb5f51d3"
      .. "4fc5104105fa20c3db75e9edeab61f900d404bfee3102471066d2dc028c21fe4"
      .. "8330039d0ad7bbea975831f657dae6609c6c6c2ee5906dd8389b6ceca6c5b286"
      .. "28dce2acc4b11a06f996e411b05e40d2152fb6259e0430587edf8bfda1f9d7d1"
      .. "a35dfde72a8b1bee7ddea0ca9cc72a532c05b1a42b089cef1943df4364561ecd"
      .. "7249965fb6b3a15ab6c63cf5399411d13c6d1e596e329c4553e3d5eef61fc21e"
      .. "861966e65a3b121598d110e38f618501fd2c0c37e3ab1d6336c8617868c7e4ea"
      .. "504be9b7ee243aea59e58cc046817653b681162bcc991378d1396d50c1399f44"
      .. "ac80e1669376781993da356b765fe5a71bd488d13ade485317020f01a3e7d906"
      .. "e26bd38c3678b9d3ee139da6d83598f7491b904f2f3121c0a45470597645cd10"
      .. "d9d6848d0e2da9e7bd8224d1a8b3511285807320a84b2ec918d1dee1b20fd060",
    K = "41ea1f81f58f7e4e4c7f1f8e739e04ffb5e29dabdc5a21b18c014f905c17f291"
      .. "e69806caeb800ccb7bbb6c1955ac61cf695c68d1ddf19a3465c465c5088ff5dd",
    M1 = "778b8aecea94608ea7971e7d73eab4abf4b211e28f3039939394fd842ee4636a"
      .. "dc9271ee44d792a757de399969c5cba80501b8bfdc82f17d0b3498f9f9ed73f8",
    M2 = "4e3e1ddbb25ad6e82c23cb8cb6606bc7a7ce8505c29fbf1902aa702be29512d8"
      .. "3adc72dc6dc6fecb80be70da5ae07d5108ed9ad047a4d5bc5913e4e31d34a940",
  },
  {
    name = "leading-zero salt (pins the minimal-length encoding)",
    password = "123-45-678",
    salt = "00b25379d1a8581eb5a727673a2441ee",
    a = "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
    b = "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
    k = "a9c2e2559bf0ebb53f0cbbf62282906bede7f2182f00678211fbd5bde5b28503"
      .. "3a4993503b87397f9be5ec02080fedbc0835587ad039060879b8621e8c3659e0",
    x = "5f71b784ad9d6a6f6e6ad9c86a78cc0013075cab4ebfc0fd507b9ad5ea4a3669"
      .. "b8fbc39e4817d06ecffba7920c1bcdd4f0ad9e2d407ba8e8b8bc6e8f6ed5e9a7",
    v = "86ef8b08203d8eb0993cb30e6bc06477d29a5f9e14abd6c163bf34f3e7c72a6b"
      .. "c109718f73d1fa4835d9dc0d7f267abeb7ef27d47de1b4f2e09767c59e6f2eca"
      .. "ab0d87c98f4d32137fdd13cafdc5b7805d9beff8d7c5eaea66f349ec5b694fb0"
      .. "410de38ea315d99988799169d966961ca6c30d537efb4150d8560d3d3c7dc2a7"
      .. "ef8075d440238d21c93cc46e85cdd360576997a5b0bf43818fe612140910ffe8"
      .. "27b5e4a4e71f850e32c99d7bf18c1fd9f642a33860b6e1e6209b9aaaba83246c"
      .. "b93d04c7f7df378734b374555f57d83f40e97573626b28d0181f4a7f5e42614b"
      .. "266be571ecf3d2a9b64524097b12504eaf88193405dc2259150828cd28c691f3"
      .. "e016c92df3941d47830aca98028d38a7e32a6d1306caea734e17cc8440e0d907"
      .. "9dd2657461055aa4a7bab8633d8b6102126ded5389148c1b225029b79d5f9ff9"
      .. "0af65ca92ff8de2e5001ae95bd7255b1ea9ae936e153af3d228611afaa6f5dbc"
      .. "d2cb90949657743d837ef1088c595ad0540bc9549b7508181810ba9ae54c4685",
    A = "fab6f5d2615d1e323512e7991cc37443f487da604ca8c9230fcb04e541dce628"
      .. "0b27ca4680b0374f179dc3bdc7553fe62459798c701ad864a91390a28c93b644"
      .. "adbf9c00745b942b79f9012a21b9b78782319d83a1f8362866fbd6f46bfc0ddb"
      .. "2e1ab6e4b45a9906b82e37f05d6f97f6a3eb6e182079759c4f6847837b62321a"
      .. "c1b4fa68641fcb4bb98dd697a0c73641385f4bab25b793584cc39fc8d48d4bd8"
      .. "67a9a3c10f8ea12170268e34fe3bbe6ff89998d60da2f3e4283cbec1393d52af"
      .. "724a57230c604e9fbce583d7613e6bffd67596ad121a8707eec4694495703368"
      .. "6a155f644d5c5863b48f61bdbf19a53eab6dad0a186b8c152e5f5d8cad4b0ef8"
      .. "aa4ea5008834c3cd342e5e0f167ad04592cd8bd279639398ef9e114dfaaab919"
      .. "e14e850989224ddd98576d79385d2210902e9f9b1f2d86cfa47ee244635465f7"
      .. "1058421a0184be51dd10cc9d079e6f1604e7aa9b7cf7883c7d4ce12b06ebe160"
      .. "81e23f27a231d18432d7d1bb55c28ae21ffcf005f57528d15a88881bb3bbb7fe",
    B = "39ca72cbb2e5b68512d3874d7b22bfe9f1543176f261a1f310e62178298dc8f2"
      .. "4133f72a7940fffbe1fb6d8e5962293ae78439e43420cb27712a48da16b35c74"
      .. "527b57c6da70223fd3281d3853fc2a643ccec161d44b2c994365bd85a514c3d0"
      .. "9294f91102e2a7783722518155281c80d92d0789c7b95b2db45e993de419fead"
      .. "440d3cf10b0ebecb9928a2b0eda1aec7232ddb0196aa60aeeafb59a23deb472c"
      .. "7afa382096d03f8a4dccb546f7416bde2aa31e592f9573efb30e5b1507ba05c7"
      .. "e9c27951c43a4faa32d7f032abc3f259f8becf8b18e18feef5ed8f5ce476de7e"
      .. "72acfd7fd13c6df5ca65ea4d203ce9c92346d04cf50a9c1dc70b38a2232147ff"
      .. "9d791da5e90ad9d335039f0a44cb80017a79b61ddcf1251cbd1621e99058fbde"
      .. "470bc6f950b862a40c6070ac98dd09a1af4e3ba9af5f26a2f92b3155b14ffb0a"
      .. "b5c33e16bd9fb6252278f1fdc96123e321f8c34d2f6eac7893a8c987fae9a78b"
      .. "6d48a0e4c6bff093ab93fa18d62411a0deee1aa1ded536a7162474777414db48",
    u = "8b30c0a71691eae700568e4d989ebeeba8857e1a624db4105302df0d572b662e"
      .. "24f150012f36189b85012601cc9997a4c22010178b765ed07de345c3def8a41c",
    S = "0e4c4f64cb62930017ec119ab50d2f1271a9999f5c8b8afaa6f5251c3cb7d5d4"
      .. "2a835ec99e0291fb4d1877ccc167184b0413939f4a6239aa538fb94c779fd0a7"
      .. "47ee2616ae45316b1a56fd0acef7c09a463779afd9a9308eb5811529440e38cf"
      .. "e94e0a37599e15ee820b096c62c944d46175f821dafdde83239df5d3d76b7772"
      .. "b58b301e278534c2c6f95dd5a6a64253dc8a96df5ec5f3399dba0bf7406bdbb4"
      .. "8196fe6db0cbec216433a9fad45a917dd47c720b746dbf4e80160bf14d1f6129"
      .. "e90910090bb3a2ec2fa0ae3928f8d92a8c49f1922c91df991425849a4c3b61f0"
      .. "c9900a7896b7a94fa87d5592e03352f2b780a4079bf34182fa88c7e2819ab476"
      .. "b4487d850878145b7263544540839e22606b7687c680d16b9221bb4ddf64dfdc"
      .. "ed5848476f9f9e4801069eab6c1c846e542f1359da348989a554ab83019cc2d5"
      .. "354ce83c190577a7fc8e0a017bf37daae759399de4087b5612f8f8ffdcbaeeef"
      .. "05b9c54eb9c03ebcc3911b9a8ce03a29ddbeb3142f1fefc20239ec1c0c40945c",
    K = "dbce5774183a5d8ad5eb70ee6be4a362f3203d73dea68806817018edd98c4c18"
      .. "b9c5a2d051318fe8ddd290f24e0376fe5265828d8f47f8355b99d13f375465f1",
    M1 = "7bfac666037a0b38b730e5c35822404d0dd8f335fc48a7868bdbabf55f098d32"
      .. "0369911f7f4e2c6f66aa8d8362686e68764149c327e905cbbe18db994a29e15d",
    M2 = "3b8b949d7943c47e06d205d13a29a51637eefe365ec3e69f58592302a44d79a1"
      .. "a5e10d753c37556c59344462d0c396dcf8ae19061971d911ddb10c04bcaae3b9",
  },
}

--- The identity HAP Pair-Setup uses; also the `I` every vector was generated with.
local HAP_USERNAME = "Pair-Setup"

--- Hex of a value zero-padded to the byte length of N, matching how the
--- generator emits `v`, `A`, `B` and `S`.
--- @param value BigNum Value
--- @return string hex 768 lowercase hex digits for group 15
local function padded_hex(value)
  return bytes.to_hex(bignum.to_bytes(value, resolve_group(srp.GROUP_3072).n_bytes))
end

--- Run comprehensive self-test with known-answer test vectors.
---
--- Every intermediate of every vector -- `k`, `x`, `v`, `A`, `u`, `S`, `K`, `M1`
--- and `M2` -- is asserted separately, so a convention that drifts shows up as a
--- named failing step rather than as "M1 is wrong". The functional tests then
--- cover private-key handling, session independence and the two RFC 5054 abort
--- conditions.
---
--- This is slow by design: a 3072-bit modular exponentiation is seconds of pure
--- Lua and each vector needs three of them.
---
--- @return boolean result True if all tests pass, false otherwise
function srp.selftest()
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

  --- Compare a hex value and print both sides when they differ.
  --- @param name string
  --- @param got string
  --- @param expected string
  local function check_hex(name, got, expected)
    check(name, got == expected)
    if got ~= expected then
      print("    expected: " .. expected)
      print("    got:      " .. got)
    end
  end

  print("Running SRP-6a test vectors (RFC 5054 group 15, SHA-512)...")
  local reference_session, reference_vector
  for _, vector in ipairs(srp_vectors) do
    print("Vector: " .. vector.name)
    local salt = bytes.from_hex(vector.salt)
    local session = srp.new({ username = HAP_USERNAME, password = vector.password })
    session:set_private(bytes.from_hex(vector.a))

    check_hex(vector.name .. " [A]", bytes.to_hex(session:get_public()), vector.A)
    session:process(salt, bytes.from_hex(vector.B))

    check_hex(vector.name .. " [k]", bignum.to_hex(session.k), vector.k)
    check_hex(vector.name .. " [x]", bignum.to_hex(session.x), vector.x)
    check_hex(vector.name .. " [v]", padded_hex(session.v), vector.v)
    check_hex(vector.name .. " [u]", bignum.to_hex(session.u), vector.u)
    check_hex(vector.name .. " [S]", padded_hex(session.S), vector.S)
    check_hex(vector.name .. " [K]", bytes.to_hex(session:get_session_key()), vector.K)
    check_hex(vector.name .. " [M1]", bytes.to_hex(session:get_proof()), vector.M1)
    check_hex(vector.name .. " [M2]", bytes.to_hex(session.M2), vector.M2)
    check(vector.name .. " [verify accepts M2]", session:verify(bytes.from_hex(vector.M2)))

    reference_session, reference_vector = session, vector
    print()
  end

  print("Running SRP-6a functional tests...")

  -- Determinism across independent session objects: same private exponent in,
  -- same A out. Compared against the vector session so this costs one
  -- exponentiation rather than two.
  check("set_private is deterministic across sessions", function()
    local other = srp.new({ username = HAP_USERNAME, password = reference_vector.password })
    other:set_private(bytes.from_hex(reference_vector.a))
    return other:get_public() == reference_session:get_public()
  end)

  check("get_public returns PAD(A), 384 bytes", function()
    return #reference_session:get_public() == 384
  end)

  check("set_private returns the session for chaining", function()
    local session = srp.new({ username = HAP_USERNAME, password = "123-45-678" })
    return session:set_private(bytes.from_hex(reference_vector.a)) == session
  end)

  check("two sessions without set_private produce different A", function()
    local one = srp.new({ username = HAP_USERNAME, password = "123-45-678" })
    local two = srp.new({ username = HAP_USERNAME, password = "123-45-678" })
    local a1, a2 = one:get_public(), two:get_public()
    return #a1 == 384 and #a2 == 384 and a1 ~= a2
  end)

  check("empty private exponent is rejected", function()
    local session = srp.new({ username = HAP_USERNAME, password = "123-45-678" })
    return pcall(session.set_private, session, "") == false
  end)

  check("zero private exponent is rejected", function()
    local session = srp.new({ username = HAP_USERNAME, password = "123-45-678" })
    return pcall(session.set_private, session, string_rep(string_char(0), 32)) == false
  end)

  -- RFC 5054 section 2.5.4: the client MUST abort when B mod N == 0. Both an
  -- all-zero B and B == N hit that, and only the second catches an
  -- implementation that tests the bytes instead of the residue.
  check("B == 0 is rejected", function()
    local session = srp.new({ username = HAP_USERNAME, password = "123-45-678" })
    session:set_private(bytes.from_hex(reference_vector.a))
    return pcall(session.process, session, "salt", string_rep(string_char(0), 384)) == false
  end)

  check("B == N (0 mod N) is rejected", function()
    local session = srp.new({ username = HAP_USERNAME, password = "123-45-678" })
    session:set_private(bytes.from_hex(reference_vector.a))
    return pcall(session.process, session, "salt", bytes.from_hex(RFC5054_3072_N_HEX)) == false
  end)

  check("empty B is rejected", function()
    local session = srp.new({ username = HAP_USERNAME, password = "123-45-678" })
    session:set_private(bytes.from_hex(reference_vector.a))
    return pcall(session.process, session, "salt", "") == false
  end)

  -- u == 0 cannot be reached with a real hash, so inject one that always
  -- returns zeros. The abort must fire on u, before any secret is derived.
  check("u == 0 is rejected", function()
    local zero_hash = {
      name = "always-zero",
      hash = function()
        return string_rep(string_char(0), 64)
      end,
    }
    local session = srp.new({ username = HAP_USERNAME, password = "123-45-678", hash = zero_hash })
    session:set_private(bytes.from_hex(reference_vector.a))
    local ok, err = pcall(session.process, session, "salt", bytes.from_hex(reference_vector.B))
    return ok == false and type(err) == "string" and err:find("u is 0", 1, true) ~= nil
  end)

  check("verify rejects a wrong M2", function()
    local wrong = bytes.from_hex(reference_vector.M2)
    wrong = string_char(0) .. wrong:sub(2)
    return reference_session:verify(wrong) == false
  end)

  check("verify rejects a truncated M2", function()
    return reference_session:verify(bytes.from_hex(reference_vector.M2):sub(1, 63)) == false
  end)

  check("verify rejects a non-string M2", function()
    return reference_session:verify(nil) == false
  end)

  check("verify accepts the correct M2", function()
    return reference_session:verify(bytes.from_hex(reference_vector.M2)) == true
  end)

  check("accessors error before process()", function()
    local session = srp.new({ username = HAP_USERNAME, password = "123-45-678" })
    return pcall(session.get_proof, session) == false
      and pcall(session.get_session_key, session) == false
      and pcall(session.verify, session, "x") == false
  end)

  check("unsupported hash name is rejected", function()
    return pcall(srp.new, { username = HAP_USERNAME, password = "x", hash = "sha1" }) == false
  end)

  check("missing username or password is rejected", function()
    return pcall(srp.new, { password = "x" }) == false
      and pcall(srp.new, { username = HAP_USERNAME }) == false
      and pcall(srp.new, nil) == false
  end)

  check("GROUP_3072 exposes N, g and the hash name", function()
    return srp.GROUP_3072.N == RFC5054_3072_N_HEX
      and srp.GROUP_3072.g == 5
      and srp.GROUP_3072.hash == "sha512"
      and #bytes.from_hex(srp.GROUP_3072.N) == 384
  end)

  print(string.format("\nSRP result: %d/%d tests passed\n", passed, total))
  return passed == total
end

--- Run performance benchmarks for the client-side SRP-6a operations.
---
--- Iteration counts are deliberately tiny: every operation below is dominated by
--- 3072-bit modular exponentiation, which is seconds per call in pure Lua. Note
--- that `benchmark_op` adds three warm-up runs on top of the count shown.
function srp.benchmark()
  local vector = srp_vectors[1]
  local salt = bytes.from_hex(vector.salt)
  local B = bytes.from_hex(vector.B)
  local a = bytes.from_hex(vector.a)
  local M2 = bytes.from_hex(vector.M2)

  local function new_session()
    return srp.new({ username = HAP_USERNAME, password = vector.password }):set_private(a)
  end

  local ready = new_session()
  ready:process(salt, B)

  print("SRP-6a client (RFC 5054 group 15, SHA-512):")
  benchmark_op("get_public (A = g^a mod N)", function()
    new_session():get_public()
  end, 3)

  benchmark_op("process (v, u, S, K, M1, M2)", function()
    ready:process(salt, B)
  end, 2)

  benchmark_op("full exchange (A + process)", function()
    local session = new_session()
    session:get_public()
    session:process(salt, B)
  end, 2)

  benchmark_op("verify (M2)", function()
    ready:verify(M2)
  end, 2000)
end

return srp
