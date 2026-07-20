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

`amalg` produces a single-file distribution from `src/crypto/init.lua`:

```bash
make build          # Output: build/crypto.lua (bitn bundled in)
```

Version is automatically injected from git tags during release.

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
