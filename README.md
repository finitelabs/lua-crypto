# lua-crypto

A pure Lua implementation of common cryptographic primitives with **zero external
dependencies** and **optional OpenSSL acceleration**. Runs on Lua 5.1, 5.2, 5.3,
5.4, and LuaJIT.

Hashing (SHA-256/512, BLAKE2), AEAD ciphers (ChaCha20-Poly1305, AES-GCM), the
Poly1305 MAC, the ChaCha20 stream cipher, and Curve25519/448 Diffie-Hellman —
portable enough to run inside sandboxed Lua hosts such as Control4 DriverWorks.

## Features

- **Zero Dependencies**: Pure Lua implementation, no C extensions required
- **Portable**: Runs on any Lua interpreter (5.1+) and LuaJIT
- **Optional OpenSSL acceleration**: Transparently prefers the host `lua-openssl`
  binding for hashing and AEAD when available, and falls back to pure Lua
  automatically
- **Well-tested**: Every module ships known-answer self-tests (RFC vectors)

## Supported Algorithms

| Category | Algorithms | Module |
| --- | --- | --- |
| Hash | SHA-256, SHA-512 (+ HMAC) | `crypto.sha256`, `crypto.sha512` |
| Hash | BLAKE2s, BLAKE2b (+ HMAC) | `crypto.blake2` |
| AEAD | ChaCha20-Poly1305 | `crypto.chacha20_poly1305` |
| AEAD | AES-GCM | `crypto.aes_gcm` |
| Stream cipher | ChaCha20 | `crypto.chacha20` |
| MAC | Poly1305 | `crypto.poly1305` |
| Diffie-Hellman | X25519 | `crypto.x25519` |
| Diffie-Hellman | X448 | `crypto.x448` |
| Signature | Ed25519 (RFC 8032) | `crypto.ed25519` |
| Key derivation | HKDF over SHA-256/SHA-512 (RFC 5869) | `crypto.hkdf` |
| PAKE | SRP-6a client, RFC 5054 group 15 + SHA-512 | `crypto.srp` |
| Big integers | Arbitrary precision, OpenSSL-preferred modexp | `crypto.bignum` |
| Randomness | CSPRNG bytes, or a hard failure | `crypto.random` |

## Randomness

Every private key this library generates comes from `crypto.random`, which draws
from `openssl.random(n, true)` or `/dev/urandom` and **raises when it can find
neither**. It will not fall back to `math.random`, which is not a CSPRNG on any
Lua implementation: on 5.1 and LuaJIT it is C `rand()`, and on 5.4+ seeding it
from the clock actively downgrades a generator the runtime had already seeded
well. A driver that fails to pair is a bug report; a driver that pairs with a
guessable long-term identity is a compromised device that looks healthy.

Unlike the accelerated primitives, this is not gated on `crypto.use_openssl()` —
that flag chooses between two correct implementations elsewhere, and it must not
be able to select a weaker source of entropy here.

```lua
local random = require("crypto.random")

if not random.available() then
  -- Neither source exists on this host; supply one rather than pairing weakly.
  random.set_source(function(n) return my_platform_csprng(n) end, "platform")
end

local seed = random.bytes(32)
```

Callers that already have entropy can keep bypassing generation entirely:
`ed25519.sign(seed, ...)`, `x25519.diffie_hellman(priv, ...)` and
`session:set_private(a)` all take key material directly and are unchanged.

## OpenSSL acceleration

The pure-Lua implementations are the baseline and always work. When the host
provides the [`lua-openssl`](https://github.com/zhaozg/lua-openssl) binding —
for example, Control4 DriverWorks exposes it beginning with OS 3.4.1 — you can
opt in to hardware-accelerated hashing and AEAD:

```lua
local crypto = require("crypto")
crypto.use_openssl(true) -- safe: falls back to pure Lua when unavailable
```

Acceleration is applied per primitive and degrades gracefully: if the binding is
missing, or a particular operation is not supported by it, the pure-Lua path is
used instead. **The Curve25519/448 Diffie-Hellman functions and Ed25519 signing
always use the pure-Lua implementations** regardless of this flag: the shipped
`lua-openssl` builds cannot perform the raw X25519/X448 operations, and no
tested build can sign with an Ed25519 key (0.11.1 over OpenSSL 3.6.3 raises
`not support ed25519`).

Capability is resolved per feature rather than assumed from a version number,
because builds of the same version differ. You can inspect what the current host
actually supports:

```lua
crypto.use_openssl(true)
local features = crypto.openssl_wrapper.features()
-- { AAD = false, BN = true, KDF = true, OKP = false, RANDOM = true }  -- e.g. Control4
```

For SRP the difference is not a matter of taste, so `crypto.srp` exposes its own
precondition instead of making callers read another module's feature map:

```lua
if not crypto.srp.is_accelerated() then
  -- 3072-bit modexp in pure Lua is ~176 s for the client exponent on a Control4
  -- controller, against ~5 ms via bn.powmod, and Lua execution is serialised
  -- across drivers there, so it blocks the whole controller. Refuse instead.
end
```

Measured behaviour of the bindings covered by CI:

| Binding | AAD | BN | KDF | OKP | Notes |
| --- | --- | --- | --- | --- | --- |
| 0.8.5 (Control4 DriverWorks) | no | yes | yes | no | `cipher:update(aad, true)` ignores the flag and encrypts the AAD as plaintext, so AEAD stays pure Lua here |
| 0.9.2 | yes | yes | yes | no | first version where AAD works |
| 0.11.1 (current upstream) | yes | yes | yes | no | |

`RANDOM` is true on all three. It is resolved outside the `use_openssl` flag,
since entropy is a capability rather than an optimisation.

Note that `bn`'s modular exponentiation is named `powmod`, not `mod_exp`, on
every build tested.

## Installation

### Option 1: Single-file Distribution (Recommended)

Download a pre-built single-file module from the
[Releases](https://github.com/finitelabs/lua-crypto/releases) page:

- **`crypto.lua`** — the canonical **core** build. Requires `bitn`
  ([lua-bitn](https://github.com/finitelabs/lua-bitn)) on the Lua path. Use this
  when composing with other libraries that already provide `bitn`, so the shared
  dependency is vendored only once.
- **`crypto-portable.lua`** — **portable** build with every dependency bundled
  in (zero external dependencies). Use this when you want a single drop-in file.

### Option 2: From Source

```bash
git clone https://github.com/finitelabs/lua-crypto.git
cd lua-crypto
```

Add the `src` and `vendor` directories to your Lua path, or copy the files into
your project.

## Usage

```lua
local crypto = require("crypto")
print(crypto.version())

-- Optionally enable OpenSSL acceleration if available
-- crypto.use_openssl(true)

-- Hashing
local digest = crypto.sha512.sha512_hex("hello world")

-- HMAC
local tag = crypto.sha256.hmac_sha256_hex(key, message)

-- AEAD: encrypt returns ciphertext..tag; decrypt returns plaintext or nil
local sealed = crypto.chacha20_poly1305.encrypt(key, nonce, plaintext, aad)
local opened = crypto.chacha20_poly1305.decrypt(key, nonce, sealed, aad)

-- Diffie-Hellman (X25519); generate_keypair() returns private, public
local alice_priv, alice_pub = crypto.x25519.generate_keypair()
local bob_priv, bob_pub = crypto.x25519.generate_keypair()
local shared_a = crypto.x25519.diffie_hellman(alice_priv, bob_pub)
local shared_b = crypto.x25519.diffie_hellman(bob_priv, alice_pub)
```

```lua
-- Ed25519 signatures
local seed, public_key = crypto.ed25519.generate_keypair()
local signature = crypto.ed25519.sign(seed, "message")
assert(crypto.ed25519.verify(public_key, "message", signature))

-- When signing repeatedly with one long-term key, expand it once. This skips
-- both the SHA-512 of the seed and the public-key scalar multiplication.
local expanded = crypto.ed25519.expand_private_key(seed)
local sig2 = crypto.ed25519.sign_expanded(expanded, public_key, "message")
```

```lua
-- HKDF key derivation
local prk = crypto.hkdf.extract("sha512", "Control-Salt", shared_secret)
local read_key = crypto.hkdf.expand("sha512", prk, "ClientEncrypt-main", 32)
local write_key = crypto.hkdf.expand("sha512", prk, "ServerEncrypt-main", 32)

-- or in one call
local key = crypto.hkdf.hkdf_sha512(salt, shared_secret, info, 32)
assert(shared_a == shared_b)
```

## Development

### Setup

```bash
# Install development dependencies (stylua, luacheck, amalg)
make install-deps
```

### Testing

```bash
make test                # Run all module self-tests
make test-sha512         # Run a specific module's self-test
make test-matrix         # Run tests across all Lua versions
make test-matrix-x25519  # Run a specific module across all Lua versions

# Or use the script directly with a custom Lua binary
LUA_BINARY=lua5.1 ./run_tests.sh
```

### Benchmarking

```bash
make bench               # Run all benchmarks
make bench-x25519        # Run a specific module benchmark

LUA_BINARY=luajit ./run_benchmarks.sh
```

### Code Quality

```bash
make check               # Run format check and lint
make format              # Format code with stylua
make lint                # Run luacheck
```

### Building

```bash
make build               # Build single-file distribution (build/crypto.lua)
make clean               # Remove generated files
```

## Security Warning

This is a pure Lua implementation intended for portability and ease of use.
While the algorithms are implemented correctly and pass their test vectors, the
implementation:

- Cannot guarantee constant-time operations
- Has not been independently audited
- Is significantly slower than native implementations (enable OpenSSL
  acceleration where available)

For production use in security-critical applications, prefer native
cryptographic libraries or the OpenSSL-accelerated path.

## License

GNU Affero General Public License v3.0 — see LICENSE file for details.

## Contributing

Contributions are welcome! Please ensure all tests pass and add new tests for
any new functionality.

---

<a href="https://www.buymeacoffee.com/derek.miller" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>
