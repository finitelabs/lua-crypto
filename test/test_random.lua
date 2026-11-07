local random = require("crypto.random")
local openssl_wrapper = require("crypto.openssl_wrapper")

--- Run the entropy-source self-test.
---
--- The contract under test is a negative one -- "never returns weak bytes" -- so
--- most of these assert that something *fails*. The no-source case is forced
--- deterministically (absent binding plus a `_urandom_path` that cannot exist)
--- rather than skipped on hosts that happen to have entropy, because that is the
--- single case where a regression is silent and catastrophic.
---
--- @return boolean result True if all tests pass, false otherwise
local function selftest()
  print("Running crypto.random entropy-source test vectors...")

  local saved_path = random._urandom_path
  local saved_preload = package.preload["openssl"]
  local saved_loaded = package.loaded["openssl"]
  local saved_use = openssl_wrapper.enabled()

  --- Force both built-in sources to be unavailable.
  local function starve()
    random.reset()
    package.loaded["openssl"] = nil
    -- Each selftest stubs the same loader independently, which the language
    -- server reads as redefining one field; that is the intent here.
    --- @diagnostic disable-next-line: duplicate-set-field
    package.preload["openssl"] = function()
      error("simulated absent binding")
    end
    openssl_wrapper.use(false) -- resets the wrapper's binding cache
    random._urandom_path = "/nonexistent/crypto-random-selftest"
  end

  --- Restore real detection, including the caller's acceleration choice, so
  --- running this inside `crypto.selftest()` cannot disturb a later module.
  local function unstarve()
    random.reset()
    package.loaded["openssl"] = saved_loaded
    package.preload["openssl"] = saved_preload
    openssl_wrapper.use(saved_use)
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

return selftest
