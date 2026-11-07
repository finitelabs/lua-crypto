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

--- Path read by the `/dev/urandom` source. Exposed only so the tests can
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

return random
