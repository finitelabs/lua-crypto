# lua-crypto Development Guide

## Project Structure

```
lua-crypto/
├── src/crypto/
│   ├── init.lua              # Module aggregator; exports primitives, use_openssl(), version(), selftest()
│   ├── sha256.lua            # SHA-256 + HMAC-SHA256
│   ├── sha512.lua            # SHA-512 + HMAC-SHA512
│   ├── blake2.lua            # BLAKE2s / BLAKE2b + HMAC
│   ├── chacha20.lua          # ChaCha20 stream cipher (RFC 8439)
│   ├── chacha20_poly1305.lua # ChaCha20-Poly1305 AEAD (RFC 8439)
│   ├── poly1305.lua          # Poly1305 MAC
│   ├── aes_gcm.lua           # AES-GCM AEAD
│   ├── x25519.lua            # Curve25519 Diffie-Hellman (always pure Lua)
│   ├── x448.lua              # Curve448 Diffie-Hellman (always pure Lua)
│   ├── ed25519.lua           # Ed25519 signatures, RFC 8032 (always pure Lua)
│   ├── hkdf.lua              # HKDF-Extract/Expand, RFC 5869 (SHA-256/512)
│   ├── bignum.lua            # Arbitrary-precision integers; OpenSSL-preferred modexp
│   ├── srp.lua               # SRP-6a client, RFC 5054 group 15 + SHA-512 (HAP)
│   ├── openssl_wrapper.lua   # Optional lua-openssl acceleration + graceful fallback
│   └── utils/
│       ├── init.lua          # Utils aggregator (bytes, benchmark)
│       ├── bytes.lua         # Byte/hex helpers
│       └── benchmark.lua     # Benchmarking utilities
├── vendor/
│   └── bitn.lua              # Vendored lua-bitn (bundled into the single-file build)
├── .github/workflows/
│   ├── build.yml             # CI: lint, test matrix, build
│   └── release.yml           # Release automation
├── run_tests.sh              # Main test runner
├── run_tests_matrix.sh       # Multi-version test runner
├── run_benchmarks.sh         # Benchmark runner
└── Makefile                  # Build automation
```

## Key Commands

```bash
make test              # Run all module self-tests
make test-sha512       # Run a specific module's self-test
make test-matrix       # Run across Lua versions
make bench             # Run benchmarks
make format            # Format code with stylua
make lint              # Lint with luacheck
make build             # Build single-file distribution (build/crypto.lua)
```

## Architecture

### Module design

`require("crypto")` returns an aggregator exposing each primitive plus:

- `crypto.use_openssl(bool)` — opt in to OpenSSL acceleration (see below)
- `crypto.version()` — build-injected version string
- `crypto.selftest()` — runs every module's known-answer self-test

Each primitive module also exposes its own `selftest()` and `benchmark()`.

### OpenSSL acceleration and fallback

`openssl_wrapper` centralizes optional acceleration via the host `lua-openssl`
binding. It is **opt-in and degrades gracefully**: `use(true)` enables it, but
every accelerated primitive falls back to its pure-Lua implementation when the
binding is unavailable or lacks the required feature. Enable via
`crypto.use_openssl(true)` or the `CRYPTO_USE_OPENSSL=1` environment variable.

Routing is deliberate and hardwired, not runtime-probed:

- **Hashing and AEAD** (SHA-256/512, ChaCha20-Poly1305, AES-GCM, …) →
  OpenSSL-preferred, pure-Lua fallback.
- **x25519 / x448** → **always pure Lua.** The shipped `lua-openssl` builds
  (e.g. Control4 DriverWorks, lua-openssl 0.8.x) can import Curve25519/448 keys
  but cannot perform the raw scalar-multiplication/derive operations — a naive
  "use OpenSSL if present" path would silently fail, so these never route to it.
- **ed25519** → **always pure Lua**, same policy and for the same reason.
  Verified on a Control4 controller (2026-08-07, lua-openssl 0.8.5):
  `pkey.new("ed25519")` fails outright, and while `pkey.read()` of an RFC 8410
  DER succeeds, `sign()` on the resulting key returns nil. `Feature.OKP` exists
  and probes for a completed sign/verify round-trip, so the unavailability is
  declarative and checkable rather than a comment; ed25519 does not consult it
  because the answer is "never route" on every build we ship to.
- **hkdf** → no route of its own. It is a thin layer over `hmac_sha256` /
  `hmac_sha512`, which already prefer OpenSSL, so it inherits acceleration
  transitively. `Feature.KDF` is declared but unused; see the rationale comment
  in `hkdf.lua`.

### Feature gating

`openssl_wrapper.get(Feature.X)` returns the module only when the binding
satisfies feature X. Features declare `{ min_version, probe? }` and resolve
lazily, once. A version floor alone cannot answer "was this build compiled with
`openssl.bn`?", so capabilities that vary between builds of the same version
carry a probe that exercises the real call and checks the answer.

Known Control4 DriverWorks facts (measured 2026-08-07, lua-openssl 0.8.5 over
OpenSSL 3.1.4), pinned as regression cases in `openssl_wrapper.selftest()`:

| Feature | Supported | Note |
|---|---|---|
| `AAD` | no | 0.8.5 < 0.9.2 floor. On 0.8.5 `cipher:update(aad, true)` ignores the flag and encrypts the AAD as plaintext, so ChaCha20-Poly1305 correctly stays pure Lua there. |
| `BN` | yes | Modular exponentiation is spelled `powmod`, not `mod_exp`. |
| `KDF` | yes | `kdf.derive` present, currently unused. |
| `OKP` | no | `pkey.new("ed25519")` fails. |

### Why bignum must use OpenSSL on Control4

Measured on a controller (2026-08-07), pure-Lua `mod_exp` over RFC 5054 group 15,
timed across exponents of 4/8/16/32/64/96 bits and fitted (R² = 0.9962):

```
ms = 4982 + 669 * exponent_bits
```

| exponent | pure Lua | `bn.powmod` | ratio |
|---|---|---|---|
| 256-bit (SRP `A = g^a mod N`) | ~176 s (2.9 min) | 5.08 ms | ~34,000x |
| 3072-bit (full width) | ~2061 s (34 min) | 60.92 ms | ~34,000x |

A full Pair-Setup client does three exponentiations, so pure Lua is on the order
of **15 minutes** against **under 0.05 s** with OpenSSL. Worse, it is not merely
slow: a direct attempt at a 256-bit exponent blocked the driver's Lua thread long
enough that the driver was reset before finishing, and while blocked the
controller stopped servicing other drivers' Lua too.

So on Control4 the pure-Lua path is a **correctness reference and a portability
fallback, not a shippable code path**. `Feature.BN` resolving true is effectively
a precondition for HAP pairing on this hardware. Anything built on `crypto.srp`
should check `crypto.openssl_wrapper.features().BN` and fail loudly rather than
silently falling back to something that will hang the controller.

### bitn dependency

The pure-Lua primitives use `bitn` (portable bitwise ops) for cross-version
support. It is vendored under `vendor/` and bundled into the single-file build.

## Testing

Every module ships a `selftest()` that runs known-answer tests (RFC/spec
vectors). The runner invokes `require("crypto.<module>").selftest()` per module:

```bash
./run_tests.sh              # all modules
./run_tests.sh sha512       # one module
make test-matrix            # across Lua 5.1–5.4 + LuaJIT
```

## Building

`amalg` produces two single-file distributions from `src/crypto/init.lua`:

```bash
make build          # Output: build/crypto.lua          (core; bitn excluded via `-i bitn`)
                    #         build/crypto-portable.lua  (all dependencies bundled)
```

`crypto.lua` is the **canonical core build**: it excludes `bitn` and expects it
on the Lua path, so it composes with other libraries that share `bitn` without
duplicating it (e.g. lua-noiseprotocol vendors this as `vendor/crypto.lua`
alongside its own `vendor/bitn.lua`). `crypto-portable.lua` bundles every
dependency for a single drop-in file with zero external requires. Version is
injected from git tags during release.

## CI/CD

- **build.yml**: on push/PR to main — stylua format check, luacheck lint, test
  matrix (Lua 5.1–5.4, LuaJIT 2.0/2.1), and single-file build.
- **release.yml**: on version tags (`v*`) — builds and publishes a release with
  the `crypto.lua` artifact.

## Code Style

- 2-space indentation
- 120 column width
- Double quotes preferred
- LuaDoc annotations for all public functions
