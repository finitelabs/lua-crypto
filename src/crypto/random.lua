--- @module "crypto.random"
--- Cryptographically secure random bytes -- or a hard failure.
---
--- Every key this library can generate is only as good as the bytes underneath
--- it. `math.random` is not a CSPRNG on any Lua implementation: on 5.1 and
--- LuaJIT it is C `rand()`, and on 5.4+ an explicit low-entropy
--- `math.randomseed` actively *downgrades* a generator the runtime had already
--- seeded well. Seeding from `os.time()` and `os.clock()` at driver startup is
--- worth roughly 20 bits, which is an offline brute force measured in seconds.
---
--- So this module has exactly one rule, and it is the reason it exists:
---
--- > **It returns strong bytes or it raises. It never returns weak bytes.**
---
--- A HAP driver that fails to pair is a bug report. A HAP driver that pairs with
--- a guessable long-term identity is a compromised controller that looks fine.
---
--- Sources, in order:
---
--- 1. `openssl.random(n, true)` -- the `strong` flag, behind `Feature.RANDOM`,
---    which probes `rand_status()` and two real draws rather than assuming.
--- 2. `/dev/urandom`.
--- 3. Nothing. `bytes()` raises.
---
--- Unlike the accelerated primitives, source 1 is resolved through
--- `openssl_wrapper.get_ungated`: `crypto.use_openssl(false)` selects a slower
--- implementation everywhere else in the library, and it must not be capable of
--- selecting a *weaker* one here.
---
--- Verified on a Control4 controller (dev, 2026-08-08): the shipped lua-openssl
--- 0.8.5 has `random` and `rand_status`, `rand_status()` is true, and
--- `random(n, true)` returns n distinct bytes. `/dev/urandom` is also readable
--- from inside the driver sandbox, so both sources are live on the target
--- hardware and neither one is theoretical. Note `random(0)` and negative
--- lengths raise on that build, which is why `bytes` validates `n` first.
---
--- @usage
--- local random = require("crypto.random")
---
--- local seed = random.bytes(32) -- raises if there is no strong source
---
--- -- Platforms with neither source can supply their own:
--- random.set_source(function(n) return my_platform_csprng(n) end, "platform")
---
--- @class crypto.random
local random = {}

local openssl_wrapper = require("crypto.openssl_wrapper")

--- Path read by the `/dev/urandom` source. Exposed only so the self-test can
--- point it at a file that does not exist and prove the failure path.
--- @type string
random._urandom_path = "/dev/urandom"

--- Resolved source: a function taking a byte count and returning a byte string.
--- @type (fun(n: integer): string|nil)|nil
local _source = nil
--- Name of the resolved source, for `random.source()`.
--- @type string|nil
local _source_name = nil
--- True once resolution has run, so a negative result is not re-probed per call.
local _resolved = false

--- Draw from the lua-openssl binding.
--- @param n integer
--- @return string|nil
local function openssl_source(n)
  local openssl = openssl_wrapper.get_ungated(openssl_wrapper.Feature.RANDOM)
  if openssl == nil then
    return nil
  end
  local ok, out = pcall(openssl.random, n, true)
  if not ok then
    return nil
  end
  return out
end

--- Draw from `/dev/urandom`.
---
--- The handle is opened per call rather than held: key generation is rare, and a
--- long-lived Control4 driver holding a file descriptor open for the life of the
--- process is a worse trade than one `open` per key.
--- @param n integer
--- @return string|nil
local function urandom_source(n)
  local ok, handle = pcall(io.open, random._urandom_path, "rb")
  if not ok or handle == nil then
    return nil
  end
  local read_ok, out = pcall(handle.read, handle, n)
  handle:close()
  if not read_ok then
    return nil
  end
  return out
end

--- Pick the first source that actually produces bytes.
---
--- Each candidate is *exercised*, not merely detected: a source that exists but
--- returns nil or a short read is rejected here rather than at the call site.
local function resolve()
  if _resolved then
    return
  end
  _resolved = true
  local candidates = {
    { name = "openssl", draw = openssl_source },
    { name = "urandom", draw = urandom_source },
  }
  for _, candidate in ipairs(candidates) do
    local ok, sample = pcall(candidate.draw, 32)
    if ok and type(sample) == "string" and #sample == 32 then
      _source = candidate.draw
      _source_name = candidate.name
      return
    end
  end
end

--- Name of the entropy source in use, resolving one if needed.
---
--- Intended for preconditions and diagnostics: a driver can refuse to start
--- pairing when this returns nil instead of discovering it mid-handshake.
--- @return string|nil name "openssl", "urandom", a custom source's name, or nil
function random.source()
  resolve()
  return _source_name
end

--- Whether a cryptographically secure source is available.
--- @return boolean available
function random.available()
  return random.source() ~= nil
end

--- Install a custom entropy source, overriding detection.
---
--- The escape hatch for a platform with neither lua-openssl nor `/dev/urandom`.
--- The function must return exactly `n` bytes; a short or non-string return is
--- rejected by `bytes()` the same way a failing built-in source would be, so a
--- broken custom source cannot quietly weaken key generation.
---
--- @param draw fun(n: integer): string|nil Returns exactly n cryptographically secure bytes
--- @param name string|nil Label reported by `random.source()` (default "custom")
function random.set_source(draw, name)
  assert(type(draw) == "function", "crypto.random: source must be a function")
  _source = draw
  _source_name = name or "custom"
  _resolved = true
end

--- Discard the current source and re-detect on next use.
function random.reset()
  _source = nil
  _source_name = nil
  _resolved = false
end

--- Generate `n` cryptographically secure random bytes.
---
--- Raises if no strong source is available, or if the source returns anything
--- other than exactly `n` bytes. It never falls back to a weak generator and
--- never returns a short result.
---
--- @param n integer Number of bytes, must be a positive integer
--- @return string bytes Exactly n cryptographically secure bytes
function random.bytes(n)
  assert(
    type(n) == "number" and n > 0 and n % 1 == 0,
    "crypto.random: byte count must be a positive integer, got " .. tostring(n)
  )
  resolve()
  if _source == nil then
    error(
      "crypto.random: no cryptographically secure entropy source available "
        .. "(tried lua-openssl RAND and "
        .. random._urandom_path
        .. "). Refusing to generate a key from a weak generator -- supply a "
        .. "source with crypto.random.set_source(fn)."
    )
  end
  local ok, out = pcall(_source, n)
  if not ok then
    error("crypto.random: entropy source '" .. tostring(_source_name) .. "' failed: " .. tostring(out))
  end
  if type(out) ~= "string" or #out ~= n then
    error(
      "crypto.random: entropy source '"
        .. tostring(_source_name)
        .. "' returned "
        .. (type(out) == "string" and (#out .. " bytes") or type(out))
        .. " instead of "
        .. n
        .. " bytes"
    )
  end
  return out
end

-- ============================================================================
-- TESTS
-- ============================================================================

--- Run the entropy-source self-test.
---
--- The contract under test is a negative one -- "never returns weak bytes" -- so
--- most of these assert that something *fails*. The no-source case is forced
--- deterministically (absent binding plus a `_urandom_path` that cannot exist)
--- rather than skipped on hosts that happen to have entropy, because that is the
--- single case where a regression is silent and catastrophic.
---
--- @return boolean result True if all tests pass, false otherwise
function random.selftest()
  print("Running crypto.random entropy-source test vectors...")

  local saved_path = random._urandom_path
  local saved_preload = package.preload["openssl"]
  local saved_loaded = package.loaded["openssl"]

  --- Force both built-in sources to be unavailable.
  local function starve()
    random.reset()
    package.loaded["openssl"] = nil
    package.preload["openssl"] = function()
      error("simulated absent binding")
    end
    openssl_wrapper.use(false) -- resets the wrapper's binding cache
    random._urandom_path = "/nonexistent/crypto-random-selftest"
  end

  --- Restore real detection, including the wrapper's initial opt-in state, so
  --- running this inside `crypto.selftest()` cannot disturb a later module.
  local function unstarve()
    random.reset()
    package.loaded["openssl"] = saved_loaded
    package.preload["openssl"] = saved_preload
    openssl_wrapper.use(os.getenv("CRYPTO_USE_OPENSSL") == "1" or os.getenv("CRYPTO_USE_OPENSSL") == "true")
    random._urandom_path = saved_path
  end

  --- Install a source returning a fixed, known byte.
  --- @param byte integer
  local function fixed_source(byte)
    random.set_source(function(n)
      return string.rep(string.char(byte), n)
    end, "fixed")
  end

  local tests = {
    {
      name = "bytes() returns the requested width",
      test = function()
        unstarve()
        if not random.available() then
          -- No entropy on this host: the contract is still testable, and the
          -- required behaviour is a raise rather than a weak result.
          return random.bytes(32) == nil
        end
        return #random.bytes(1) == 1 and #random.bytes(32) == 32 and #random.bytes(384) == 384
      end,
    },
    {
      name = "two draws differ",
      test = function()
        unstarve()
        if not random.available() then
          return true
        end
        return random.bytes(32) ~= random.bytes(32)
      end,
    },
    {
      name = "no source available raises instead of returning weak bytes",
      test = function()
        starve()
        if random.available() then
          return false
        end
        local ok, err = pcall(random.bytes, 32)
        return ok == false and tostring(err):find("no cryptographically secure") ~= nil
      end,
    },
    {
      name = "a source returning short output is rejected, not passed through",
      test = function()
        random.set_source(function(n)
          return string.rep("A", n - 1)
        end, "short")
        local ok, err = pcall(random.bytes, 32)
        return ok == false and tostring(err):find("31 bytes") ~= nil
      end,
    },
    {
      name = "a source returning nil is rejected",
      test = function()
        random.set_source(function()
          return nil
        end, "nilsource")
        return pcall(random.bytes, 32) == false
      end,
    },
    {
      name = "a raising source is reported, not swallowed",
      test = function()
        random.set_source(function()
          error("device gone")
        end, "raising")
        local ok, err = pcall(random.bytes, 32)
        return ok == false and tostring(err):find("device gone") ~= nil
      end,
    },
    {
      name = "a custom source is used verbatim",
      test = function()
        fixed_source(122)
        return random.source() == "fixed" and random.bytes(4) == "zzzz"
      end,
    },
    {
      name = "reset() restores detection",
      test = function()
        fixed_source(122)
        random.reset()
        unstarve()
        return random.source() ~= "fixed"
      end,
    },
    {
      name = "non-positive and fractional widths are rejected",
      test = function()
        unstarve()
        return pcall(random.bytes, 0) == false
          and pcall(random.bytes, -1) == false
          and pcall(random.bytes, 1.5) == false
          and pcall(random.bytes, "32") == false
      end,
    },
    {
      name = "openssl is preferred over urandom when the binding supports RANDOM",
      test = function()
        random.reset()
        local draws = 0
        package.preload["openssl"] = nil
        package.loaded["openssl"] = {
          version = function()
            return "0.8.5"
          end,
          rand_status = function()
            return true
          end,
          random = function(n)
            draws = draws + 1
            -- Distinct per call so the RANDOM probe's two-draw check passes.
            return string.rep(string.char(draws % 256), n)
          end,
        }
        openssl_wrapper.use(false) -- reset the binding cache; RANDOM is ungated
        local name = random.source()
        return name == "openssl" and draws > 0
      end,
    },
    {
      name = "a binding whose rand_status is false is not used",
      test = function()
        random.reset()
        package.preload["openssl"] = nil
        package.loaded["openssl"] = {
          version = function()
            return "0.8.5"
          end,
          rand_status = function()
            return false
          end,
          random = function(n)
            return string.rep("\0", n)
          end,
        }
        openssl_wrapper.use(false)
        random._urandom_path = "/nonexistent/crypto-random-selftest"
        return random.available() == false
      end,
    },
    {
      name = "a binding whose RNG returns a constant is not used",
      test = function()
        random.reset()
        package.preload["openssl"] = nil
        package.loaded["openssl"] = {
          version = function()
            return "0.8.5"
          end,
          rand_status = function()
            return true
          end,
          random = function(n)
            return string.rep("\0", n)
          end,
        }
        openssl_wrapper.use(false)
        random._urandom_path = "/nonexistent/crypto-random-selftest"
        return random.available() == false
      end,
    },
    {
      -- Required lazily: those modules depend on crypto.random, not the other
      -- way round, and this check belongs with the guarantee it protects.
      name = "key generators return exactly the bytes this module supplied",
      test = function()
        local generators = {
          { require("crypto.ed25519").generate_private_key, 32 },
          { require("crypto.x25519").generate_private_key, 32 },
          { require("crypto.x448").generate_private_key, 56 },
        }
        for _, entry in ipairs(generators) do
          local generate, width = entry[1], entry[2]
          fixed_source(42)
          local out = generate()
          if type(out) ~= "string" or out ~= string.rep(string.char(42), width) then
            return false
          end
        end
        return true
      end,
    },
    {
      -- Checked by width rather than by output: `get_public` would otherwise
      -- have to run a 3072-bit modular exponentiation to prove the point.
      name = "srp draws its private exponent here, 32 bytes wide",
      test = function()
        local requested = nil
        random.set_source(function(n)
          requested = n
          error("stop before the modexp")
        end, "recording")
        local session = require("crypto.srp").new({ username = "Pair-Setup", password = "123-45-678" })
        pcall(session.get_public, session)
        return requested == 32
      end,
    },
    {
      name = "every key generator raises when there is no entropy source",
      test = function()
        local session = require("crypto.srp").new({ username = "Pair-Setup", password = "123-45-678" })
        local generators = {
          require("crypto.ed25519").generate_private_key,
          require("crypto.x25519").generate_private_key,
          require("crypto.x448").generate_private_key,
          function()
            return session:get_public()
          end,
        }
        for _, generate in ipairs(generators) do
          starve()
          if pcall(generate) ~= false then
            return false
          end
        end
        return true
      end,
    },
  }

  local passed = 0
  for _, test in ipairs(tests) do
    local ok, result = pcall(test.test)
    if ok and result == true then
      print("  ✅ PASS: " .. test.name)
      passed = passed + 1
    else
      print("  ❌ FAIL: " .. test.name .. (ok and "" or (" - " .. tostring(result))))
    end
  end

  unstarve()

  print(string.format("\ncrypto.random result: %d/%d tests passed\n", passed, #tests))
  return passed == #tests
end

return random
