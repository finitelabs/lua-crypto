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
│   ├── random.lua            # CSPRNG bytes; raises rather than returning weak ones
│   ├── bignum.lua            # Arbitrary-precision integers; OpenSSL-preferred modexp
│   ├── srp.lua               # SRP-6a client, RFC 5054 group 15 + SHA-512 (HAP)
│   ├── openssl_wrapper.lua   # Optional lua-openssl acceleration + graceful fallback
│   ├── annotations.lua       # Shared LuaCATS aliases (workspace-wide; not require'd)
│   └── utils/
│       ├── init.lua          # Utils aggregator (bytes, benchmark)
│       ├── bytes.lua         # Byte/hex helpers
│       └── benchmark.lua     # Benchmarking utilities
├── vendor/
│   └── bitn.lua              # Vendored lua-bitn (bundled into the single-file build)
├── tools/
│   └── generate_srp_vectors.py  # Regenerates the SRP vectors in srp.lua
├── .github/workflows/
│   ├── build.yml             # CI: check, test matrix, openssl-matrix, build
│   └── release.yml           # Release automation
├── .luarc-typecheck.json     # Hardened config for `make typecheck` (see below)
├── .luacheckrc
├── run_tests.sh              # Main test runner
├── run_tests_matrix.sh       # Multi-version test runner
├── run_benchmarks.sh         # Benchmark runner
├── run_benchmarks_matrix.sh
└── Makefile                  # Build automation
```

## Key Commands

```bash
make test              # Run all module self-tests
make test-sha512       # Run a specific module's self-test
make test-matrix       # Run across Lua versions
make bench             # Run benchmarks
make format            # Format code with stylua
make format-check      # Verify formatting without rewriting
make lint              # Lint with luacheck
make typecheck         # Check LuaCATS annotations with lua-language-server
make check             # Full gate: format-check + lint + typecheck
make build             # Build single-file distribution (build/crypto.lua)
```

`make check` is the gate CI runs. `make all` is `format lint test build`, which
rewrites `src/` in place and runs neither `format-check` nor `typecheck` — it is
not a substitute for `check`.

### typecheck

`make typecheck` runs lua-language-server against the committed
`.luarc-typecheck.json`. It catches what luacheck does not: undefined or duplicate
`@alias`, returns that disagree with `@return`, fields missing from a `@class`.

It checks the whole repo rather than `src/` alone. `@alias` resolves
workspace-wide — which is why `src/crypto/annotations.lua` is never `require`d by
anything and still matters — so a narrower scope gives *different* findings, not
fewer.

`--configpath` displaces each individual setting the committed config declares,
not each table, so a knob is only closed if it is named. Suppression keys can be
enumerated from the diagnostics read sites — the paths below are inside a
lua-language-server source checkout, not this repo:

    grep -rhoE "config\.get\([^,]*, *'Lua\.[A-Za-z.]+'" \
      script/core/diagnostics/*.lua script/provider/diagnostic.lua

Treat that as a floor, not a ceiling: its file scope is the shape of its blind
spot. Anything that gates file loading or rewrites source before analysis is read
elsewhere, and has to be enumerated separately from `script/plugin.lua` and
`script/workspace.lua`. `runtime.plugin` is the case that matters, and the grep
cannot surface it by construction. `check_worker.lua` does `require 'plugin'`, so
an `OnSetText` returning an empty edit blanks every file in the repo and the check
passes having analysed nothing.

Two traps decide how a key gets declared, and neither is answered by the key's
type:

Empty is not always inert, so read the read site. `neededFileStatus` and
`groupFileStatus` are per-key lookups that fall back to the built-in default, so
`{}` leaves behaviour untouched. `enableScheme` defaults to `["file"]`, which makes
`[]` silence the whole check exactly as a local `["git"]` would. It is declared as
`["file"]` for that reason.

Immunity is per-code, so one planted probe does not measure a key.
`check_worker.lua`'s `downgrade_checks_to_opened` force-overwrites only codes whose
default status is `Any`, leaving everything defaulting to `Opened` under local
control, which is precisely the type-check group this gate exists for. An
`undefined-global` probe therefore reports `neededFileStatus` as inert while a
`return-type-mismatch` probe shows it silencing the check. Probe with a type-check
code.

Any setting `.luarc-typecheck.json` does not name, under any table, is still
reachable from a local `.luarc.json`. Re-run both enumerations when upgrading the
server rather than assuming the list stayed complete.

`vendor/` is both a `library` and an `ignoreDir`: `ignoreDir` keeps the vendored
code from being diagnosed here, `library` keeps its definitions resolvable.
`runtime.version` is pinned to LuaJIT because that is what Control4 runs.

The server version is not pinned locally. `install-deps` takes whatever Homebrew
has while CI pins 3.19.0, so compare the version the target prints if a local
result disagrees with CI.

Part of `check`, so CI enforces it.

## Architecture

### Module design

`require("crypto")` returns an aggregator exposing each primitive plus:

- `crypto.use_openssl(bool)` — opt in to OpenSSL acceleration (see below)
- `crypto.version()` — build-injected version string
- `crypto.selftest()` — runs every module's known-answer self-test

Each primitive module also exposes its own `selftest()`. Most, but not all, also
expose `benchmark()` — `random` and `openssl_wrapper` have none. `crypto.selftest()`
guards with `type(mod.selftest) == "function"` rather than assuming the shape.

### OpenSSL acceleration and fallback

`openssl_wrapper` centralizes optional acceleration via the host `lua-openssl`
binding. It is **opt-in and degrades gracefully**: `use(true)` enables it, but
every accelerated primitive falls back to its pure-Lua implementation when the
binding is unavailable or lacks the required feature. Enable via
`crypto.use_openssl(true)` or the `CRYPTO_USE_OPENSSL=1` environment variable.

Routing is deliberate and hardwired, not runtime-probed:

- **Hashing and AEAD** (SHA-256/512, BLAKE2, ChaCha20, ChaCha20-Poly1305,
  AES-GCM) → OpenSSL-preferred, pure-Lua fallback. Standalone `poly1305` is not
  among them and is never accelerated.
- **x25519 / x448** → **always pure Lua.** The shipped `lua-openssl` builds
  (e.g. Control4 DriverWorks, lua-openssl 0.8.x) can import Curve25519/448 keys
  but cannot perform the raw scalar-multiplication/derive operations — a naive
  "use OpenSSL if present" path would silently fail, so these never route to it.
- **ed25519** → **always pure Lua**, same policy and for the same reason.
  Verified on a Control4 controller (2026-08-07, lua-openssl 0.8.5):
  `pkey.new("ed25519")` fails outright, and while `pkey.read()` of an RFC 8410
  DER succeeds, `sign()` on the resulting key returns nil. `Feature.OKP` exists
  and probes for a completed sign/verify round-trip; ed25519 does not consult it
  because the answer is "never route" on every build we ship to. This is not an
  artefact of Control4's old binding: lua-openssl 0.11.1 over OpenSSL 3.6.3
  rejects `pkey.new("ed25519")` with `not support ed25519!!!!` as well
  (measured 2026-08-08), so the pure-Lua route is the current state of the
  binding rather than a workaround for one embedded build.
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
OpenSSL 3.1.4). These are regression-tested by the `openssl-matrix` CI job, which
installs the real `0.8.5-1`, `0.9.2-2` and `0.11.1-1` rocks and asserts the feature
map against each. `openssl_wrapper.selftest()` also covers this ground, but it
drives *injected stand-in bindings* rather than a real one, so it pins the gate's
verdict for a version string rather than the binding's behaviour:

| Feature | Supported | Note |
|---|---|---|
| `AAD` | no | 0.8.5 < 0.9.2 floor. On 0.8.5 `cipher:update(aad, true)` ignores the flag and encrypts the AAD as plaintext, so ChaCha20-Poly1305 correctly stays pure Lua there. |
| `BN` | yes | Modular exponentiation is spelled `powmod` on this build. The wrapper accepts either spelling (`bn.powmod` or `bn.mod_exp`) and both are pinned. |
| `KDF` | yes | `kdf.derive` present, currently unused. |
| `OKP` | no | `pkey.new("ed25519")` fails. |
| `RANDOM` | yes | `random` and `rand_status` both present, `rand_status()` true, `random(n, true)` returns n distinct bytes (measured 2026-08-08). `random(0)` and negative lengths raise. |

### Nothing is accelerated until `crypto.use_openssl(true)` is called

`CRYPTO_USE_OPENSSL` is not set in the DriverWorks environment, so on Control4
an explicit call is the only thing that turns acceleration on. **Call
`crypto.use_openssl(true)` during driver init, before any crypto work and
before any feature query.**

A driver that skips the call runs pure Lua everywhere -- measured on the dev
controller (2026-08-08), SHA-512 over 1 KiB goes from 0.016 ms to
82.05 ms, a factor of about 5,100. `openssl_wrapper.features()` reports every
feature false on hardware where four of the five are true, because it reports
what `get` would return rather than what the binding can do. And
`srp.is_accelerated()` returns false, so a HAP caller following the guidance
below fails closed on a controller that was perfectly capable.

Both readings produce the same `false` and need opposite responses, so
`bignum.is_accelerated()` and `srp.is_accelerated()` return a second value
naming which one it is:

```lua
local ok, why = crypto.srp.is_accelerated()
if not ok then
  -- "OpenSSL acceleration is not enabled: call crypto.use_openssl(true) ..."
  -- "the lua-openssl binding is not available on this host"
  -- "the lua-openssl binding does not support BN"
  -- "the lua-openssl binding failed bignum's multi-limb known-answer check ..."
  -- "OpenSSL modular exponentiation is unavailable"  (fallback when the
  --   wrapper has no more specific reason; do not match only the four above)
  error("SRP unusable: " .. why)
end
```

Fail closed on the boolean, log the reason. The first string is a one-line fix;
the rest are not.

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
should check **`crypto.srp.is_accelerated()`** and fail loudly rather than
silently falling back to something that will hang the controller.

That accessor delegates to `bignum.is_accelerated()`, which applies both of the
conditions `mod_exp` applies: the feature gate *and* the multi-limb known-answer
check on the binding. `openssl_wrapper.features().BN` is not a substitute — it
reports true for a binding `bignum` has already decided not to trust.

### What the asymmetric primitives cost on Control4

X25519 and Ed25519 are always pure Lua (see the routing list above), so unlike
SRP their cost does not move with the acceleration flag. These are what HAP
Pair-Verify is built out of, measured with `build/crypto-portable.lua` on the
dev controller (2026-08-08, OS 4.2.1.757028-res, lua-openssl 0.8.5). Every
figure was taken in the same call as its RFC vector check, so they time a
correct implementation rather than a fast wrong one.

| operation | per op | vector |
|---|---|---|
| X25519 scalar multiplication | 0.459 s | RFC 7748 6.1 |
| Ed25519 sign, cold from seed | 1.602 s | RFC 8032 7.1 |
| Ed25519 sign, pre-expanded | 0.786 s | RFC 8032 7.1 |
| Ed25519 `expand_private_key` | < 0.001 s | |
| Ed25519 verify | 1.583 s | |

Loading the 519 KB portable build costs 0.065 s to parse plus 0.009 s to
execute, which lands in driver startup and is cheap enough to ignore.

Two consequences for anything building HAP on top of this:

- **Cache the expanded key _and_ the public key.** `sign_expanded` is 2.04x faster
  than `sign`, but `expand_private_key` is free at this resolution, so the 0.816 s
  difference is not the expansion. `ed25519.sign` also derives the public key on
  every call — `pt_scalarbase` + `pt_pack` — before delegating to
  `sign_expanded(expanded, public_key, message)`. A caller that holds only the
  expanded form still pays that scalar multiplication and sees none of the 2.04x.
  Hold both. A full Pair-Verify is two scalar multiplications, one sign and one
  verify: `2(0.459) + 0.786 + 1.583 = 3.29 s`, which is workable only with a
  persistent session.
- **Do not run the chain synchronously.** A single 1.583 s verify holds the Lua
  thread long enough to starve other drivers, the same failure the unaccelerated
  `mod_exp` produces above. Pair-Verify needs its steps spread across timer
  callbacks.

### Randomness is a capability, not an optimisation

`crypto.random` returns cryptographically secure bytes or raises. There is no
weak fallback anywhere in the library: the `math.randomseed(os.time() +
os.clock() * 1000000)` idiom was worth roughly 20 bits at driver startup, and on
5.4+ it actively downgrades a generator the runtime had already seeded well.

Sources in order: `openssl.random(n, true)` behind `Feature.RANDOM`, then
`/dev/urandom`, then failure. Both are live on a Control4 controller -- the
0.8.5 binding's RNG works, and `/dev/urandom` is readable from inside the driver
sandbox (measured 2026-08-08).

It resolves through `openssl_wrapper.get_ungated`, not `get`, so the acceleration
flag does not gate it: everywhere else the flag picks between two correct
implementations, here it would pick between a correct one and a broken one.

Callers holding their own entropy are unaffected -- `ed25519.sign(seed, ...)`,
`x25519.diffie_hellman(priv, ...)` and the SRP `Session:set_private(a)`
(`src/crypto/srp.lua`) all take key material directly. Hosts with neither source
can install one with `random.set_source(draw, name)`.

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

- **build.yml**: on push/PR to `main` or `master`.
  - `check` — `make check` (format-check, luacheck, typecheck against
    lua-language-server 3.19.0).
  - `test` — `make test-all` across Lua 5.1–5.4 and LuaJIT 2.0/2.1.
  - `openssl-matrix` — installs the real `lua-openssl` rocks `0.8.5-1`, `0.9.2-2`
    and `0.11.1-1` and runs the suite against each with acceleration both on and
    off. This is the only place the DriverWorks feature table above is checked
    against a real binding rather than a stand-in, so a change to
    `openssl_wrapper` that passes `check` and `test` can still fail here.
  - `build` — single-file distributions.
- **release.yml**: on version tags (`v*`) — publishes **both** `build/crypto.lua`
  and `build/crypto-portable.lua`. (build.yml's artifact upload keeps only
  `crypto.lua`; the release carries both.)

## Code Style

- 2-space indentation
- 120 column width
- Double quotes preferred
- LuaCATS annotations on public functions

stylua and luacheck are invoked with these as CLI flags from the Makefile and
cover `src/` only; there is no `.stylua.toml`. `.luacheckrc` sets
`max_line_length = false`, so the 120-column limit is enforced by stylua alone.
`typecheck` deliberately runs over the whole repo instead — see above.
Annotations are validated where they exist but are nowhere required.
