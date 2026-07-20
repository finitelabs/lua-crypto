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
used instead. **The Curve25519/448 Diffie-Hellman functions always use the
pure-Lua implementations** regardless of this flag, because the shipped
`lua-openssl` builds cannot perform the raw X25519/X448 operations.

## Installation

### Option 1: Single-file Distribution (Recommended)

Download a pre-built single-file module from the
[Releases](https://github.com/finitelabs/lua-crypto/releases) page:

- **`crypto.lua`** — complete bundle with all dependencies included (zero
  external dependencies)

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

-- Diffie-Hellman (X25519)
local alice = crypto.x25519.generate_keypair()
local bob = crypto.x25519.generate_keypair()
local shared_a = crypto.x25519.diffie_hellman(alice.private_key, bob.public_key)
local shared_b = crypto.x25519.diffie_hellman(bob.private_key, alice.public_key)
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
