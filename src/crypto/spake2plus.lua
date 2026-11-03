--- @module "crypto.spake2plus"
--- SPAKE2+, RFC 9383, for the ciphersuite P256-SHA256-HKDF-SHA256-HMAC-SHA256
--- with the RFC's M and N. No other suite is offered.
---
--- Both roles are here. The prover knows the password, so both w0 and w1; it
--- is the side a client runs. The verifier holds w0 and the registration record
--- L = w1*G; it is here for tests and for stand-in devices.
---
--- RFC 9383 leaves the password-to-(w0, w1) step to the application, and so
--- does this module: run the application's PBKDF (`crypto.pbkdf2`, for example)
--- and reduce each half of its output with `crypto.p256.reduce`. w0, w1, x and
--- y are 32-byte big-endian scalars in [0, n-1]; `crypto.p256.random_scalar`
--- makes x and y.
---
--- Points go out as 65-byte uncompressed SEC 1. Peer points may arrive
--- compressed or uncompressed, are validated, and are always written into the
--- transcript uncompressed. An invalid peer point, or a Z or V that comes out as
--- the identity, makes the `*_finish` functions return nil and a reason.
---
--- Pacing
--- ------
--- Each call is up to three P-256 scalar multiplications: about 53 ms each
--- through OpenSSL on a Control4 controller, more in pure Lua (see
--- `crypto.p256`). Lua runs one driver at a time there, so `opts.step`, if
--- given, is called between consecutive multiplications and nothing else. A
--- caller that runs the exchange inside a coroutine can pass a function that
--- yields and resume it from a timer, one multiplication per tick. Check
--- `is_accelerated()` before starting.
---
--- @usage
--- local p256 = require("crypto.p256")
--- local spake2plus = require("crypto.spake2plus")
---
--- local x = p256.random_scalar()
--- send(spake2plus.prover_share(w0, x)) -- X, 65 bytes
--- local result = assert(spake2plus.prover_finish(w0, w1, x, X, Y, context, "client", "server"))
--- -- Check the verifier's confirmV against result.verifier_confirm in constant
--- -- time before sending result.prover_confirm or using result.shared_key.
---
--- @class crypto.spake2plus
local spake2plus = {}

local hkdf = require("crypto.hkdf")
local p256 = require("crypto.p256")
local random = require("crypto.random")
local sha256 = require("crypto.sha256")
local utils = require("crypto.utils")
local bytes = utils.bytes
local benchmark_op = utils.benchmark.benchmark_op

-- Local references for performance
local floor = math.floor
local string_char = string.char
local string_sub = string.sub
local table_concat = table.concat

-- ============================================================================
-- CONSTANTS AND TYPES
-- ============================================================================

-- RFC 9383 section 4, P-256: M and N, uncompressed as they appear in the
-- Appendix C transcript. The section 4 compressed forms are checked against
-- these by the selftest.
local M_HEX = "04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
  .. "5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20"
local N_HEX = "04d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
  .. "07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7"
local M_COMPRESSED_HEX = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
local N_COMPRESSED_HEX = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"

local M_BYTES = bytes.from_hex(M_HEX)
local N_BYTES = bytes.from_hex(N_HEX)

--- Options shared by the share and finish functions.
--- @class crypto.spake2plus.Options
--- @field step? fun() Called between consecutive scalar multiplications

--- What both roles derive. The confirmations are named by who sends them.
--- @class crypto.spake2plus.Result
--- @field shared_key string K_shared, 32 bytes
--- @field prover_confirm string confirmP = HMAC-SHA256(K_confirmP, Y): the prover sends it, the verifier checks it
--- @field verifier_confirm string confirmV = HMAC-SHA256(K_confirmV, X): the verifier sends it, the prover checks it
--- @field transcript string TT, for debugging. It ends with w0, so it is as secret as the password: never log it

--- Intermediate values, for the selftest.
--- @class Spake2plusDetail
--- @field Z string Uncompressed
--- @field V string Uncompressed
--- @field K_main string
--- @field K_confirmP string
--- @field K_confirmV string

--- M and N as points, decoded on first use.
--- @type crypto.p256.Point?, crypto.p256.Point?
local m_point, n_point

--- @return crypto.p256.Point M
--- @return crypto.p256.Point N
local function constants()
  if m_point == nil or n_point == nil then
    m_point = assert(p256.decode_point(M_BYTES))
    n_point = assert(p256.decode_point(N_BYTES))
  end
  return m_point, n_point
end

-- ============================================================================
-- INTERNAL HELPERS
-- ============================================================================

--- Raise unless `value` is a 32-byte scalar.
--- @param name string
--- @param value any
local function check_scalar(name, value)
  if type(value) ~= "string" or #value ~= 32 then
    error("SPAKE2+: " .. name .. " must be a 32-byte big-endian scalar", 3)
  end
end

--- The step callback from `opts`, or a no-op.
--- @param opts crypto.spake2plus.Options?
--- @return fun() step
local function stepper(opts)
  if opts == nil then
    return function() end
  end
  if type(opts) ~= "table" then
    error("SPAKE2+: opts must be a table", 3)
  end
  local step = opts.step
  if step == nil then
    return function() end
  end
  if type(step) ~= "function" then
    error("SPAKE2+: opts.step must be a function", 3)
  end
  return step
end

--- An optional transcript string, "" when absent.
--- @param name string
--- @param value any
--- @return string
local function optional_string(name, value)
  if value == nil then
    return ""
  end
  if type(value) ~= "string" then
    error("SPAKE2+: " .. name .. " must be a string", 3)
  end
  return value
end

--- Append len(value) || value, the length as an 8-byte little-endian integer.
--- @param parts string[]
--- @param value string
local function append_prefixed(parts, value)
  local n = #value
  local length = {}
  for i = 1, 8 do
    length[i] = string_char(n % 256)
    n = floor(n / 256)
  end
  parts[#parts + 1] = table_concat(length)
  parts[#parts + 1] = value
end

--- Decode a point for the exchange, naming it in the error.
--- @param name string
--- @param encoded any
--- @return crypto.p256.Point? point
--- @return string? err
local function decode(name, encoded)
  local point, err = p256.decode_point(encoded)
  if point == nil then
    return nil, "SPAKE2+: invalid " .. name .. ": " .. tostring(err)
  end
  return point
end

--- Build TT from the shared values and run the key schedule (RFC 9383 3.3, 3.4).
--- @param context string
--- @param id_prover string
--- @param id_verifier string
--- @param X crypto.p256.Point
--- @param Y crypto.p256.Point
--- @param Z crypto.p256.Point
--- @param V crypto.p256.Point
--- @param w0 string
--- @return crypto.spake2plus.Result? result
--- @return Spake2plusDetail|string detail Intermediate values, or why it failed
local function key_schedule(context, id_prover, id_verifier, X, Y, Z, V, w0)
  if p256.is_identity(Z) or p256.is_identity(V) then
    return nil, "SPAKE2+: Z or V is the identity; the peer's share is invalid"
  end
  local X_bytes = p256.encode_point(X)
  local Y_bytes = p256.encode_point(Y)
  local Z_bytes = p256.encode_point(Z)
  local V_bytes = p256.encode_point(V)

  local parts = {}
  for _, value in ipairs({ context, id_prover, id_verifier, M_BYTES, N_BYTES, X_bytes, Y_bytes, Z_bytes, V_bytes, w0 }) do
    append_prefixed(parts, value)
  end
  local transcript = table_concat(parts)

  local K_main = sha256.sha256(transcript)
  local confirmation_keys = hkdf.derive("sha256", nil, K_main, "ConfirmationKeys", 64)
  local K_confirmP = string_sub(confirmation_keys, 1, 32)
  local K_confirmV = string_sub(confirmation_keys, 33, 64)

  return {
    shared_key = hkdf.derive("sha256", nil, K_main, "SharedKey", 32),
    prover_confirm = sha256.hmac_sha256(K_confirmP, Y_bytes),
    verifier_confirm = sha256.hmac_sha256(K_confirmV, X_bytes),
    transcript = transcript,
  }, {
    Z = Z_bytes,
    V = V_bytes,
    K_main = K_main,
    K_confirmP = K_confirmP,
    K_confirmV = K_confirmV,
  }
end

--- The prover's side of the finish, with intermediates.
--- @return crypto.spake2plus.Result? result
--- @return Spake2plusDetail|string detail
local function prover_compute(w0, w1, x, X, Y, context, id_prover, id_verifier, opts)
  check_scalar("w0", w0)
  check_scalar("w1", w1)
  check_scalar("x", x)
  context = optional_string("context", context)
  id_prover = optional_string("id_prover", id_prover)
  id_verifier = optional_string("id_verifier", id_verifier)
  local step = stepper(opts)

  local X_point, x_err = decode("X", X)
  if X_point == nil then
    return nil, tostring(x_err)
  end
  local Y_point, y_err = decode("Y", Y)
  if Y_point == nil then
    return nil, tostring(y_err)
  end

  local _, N = constants()
  local U = p256.sub(Y_point, p256.mul(w0, N))
  step()
  local Z = p256.mul(x, U)
  step()
  local V = p256.mul(w1, U)
  return key_schedule(context, id_prover, id_verifier, X_point, Y_point, Z, V, w0)
end

--- The verifier's side of the finish, with intermediates.
--- @return crypto.spake2plus.Result? result
--- @return Spake2plusDetail|string detail
local function verifier_compute(w0, L, y, X, Y, context, id_prover, id_verifier, opts)
  check_scalar("w0", w0)
  check_scalar("y", y)
  context = optional_string("context", context)
  id_prover = optional_string("id_prover", id_prover)
  id_verifier = optional_string("id_verifier", id_verifier)
  local step = stepper(opts)

  local L_point, l_err = decode("L", L)
  if L_point == nil then
    return nil, tostring(l_err)
  end
  local X_point, x_err = decode("X", X)
  if X_point == nil then
    return nil, tostring(x_err)
  end
  local Y_point, y_err = decode("Y", Y)
  if Y_point == nil then
    return nil, tostring(y_err)
  end

  local M = constants()
  local T = p256.sub(X_point, p256.mul(w0, M))
  step()
  local Z = p256.mul(y, T)
  step()
  local V = p256.mul(y, L_point)
  return key_schedule(context, id_prover, id_verifier, X_point, Y_point, Z, V, w0)
end

-- ============================================================================
-- PUBLIC INTERFACE
-- ============================================================================

--- The prover's share, X = x*G + w0*M.
--- @param w0 string 32-byte scalar
--- @param x string 32-byte scalar, fresh and secret
--- @param opts? crypto.spake2plus.Options
--- @return string X 65 bytes, uncompressed
function spake2plus.prover_share(w0, x, opts)
  check_scalar("w0", w0)
  check_scalar("x", x)
  local step = stepper(opts)
  local M = constants()
  local xG = p256.mul_base(x)
  step()
  return p256.encode_point(p256.add(xG, p256.mul(w0, M)))
end

--- The prover's finish: validate Y, derive Z = x*(Y - w0*N) and
--- V = w1*(Y - w0*N), and run the key schedule.
---
--- @param w0 string 32-byte scalar
--- @param w1 string 32-byte scalar
--- @param x string The scalar `prover_share` used
--- @param X string The share `prover_share` returned
--- @param Y string The verifier's share, compressed or uncompressed
--- @param context? string Application context ("" when nil)
--- @param id_prover? string Prover identity ("" when nil)
--- @param id_verifier? string Verifier identity ("" when nil)
--- @param opts? crypto.spake2plus.Options
--- @return crypto.spake2plus.Result? result
--- @return string? err Why the exchange failed: an invalid point, or Z or V the identity
function spake2plus.prover_finish(w0, w1, x, X, Y, context, id_prover, id_verifier, opts)
  local result, detail = prover_compute(w0, w1, x, X, Y, context, id_prover, id_verifier, opts)
  if result == nil then
    return nil, tostring(detail)
  end
  return result
end

--- The verifier's registration record, L = w1*G.
--- @param w1 string 32-byte scalar
--- @return string L 65 bytes, uncompressed
function spake2plus.registration(w1)
  check_scalar("w1", w1)
  return p256.encode_point(p256.mul_base(w1))
end

--- The verifier's share, Y = y*G + w0*N.
--- @param w0 string 32-byte scalar
--- @param y string 32-byte scalar, fresh and secret
--- @param opts? crypto.spake2plus.Options
--- @return string Y 65 bytes, uncompressed
function spake2plus.verifier_share(w0, y, opts)
  check_scalar("w0", w0)
  check_scalar("y", y)
  local step = stepper(opts)
  local _, N = constants()
  local yG = p256.mul_base(y)
  step()
  return p256.encode_point(p256.add(yG, p256.mul(w0, N)))
end

--- The verifier's finish: validate X, derive Z = y*(X - w0*M) and V = y*L, and
--- run the key schedule. The result has the same shape as `prover_finish`'s.
---
--- @param w0 string 32-byte scalar
--- @param L string Registration record from `registration`
--- @param y string The scalar `verifier_share` used
--- @param X string The prover's share, compressed or uncompressed
--- @param Y string The share `verifier_share` returned
--- @param context? string Application context ("" when nil)
--- @param id_prover? string Prover identity ("" when nil)
--- @param id_verifier? string Verifier identity ("" when nil)
--- @param opts? crypto.spake2plus.Options
--- @return crypto.spake2plus.Result? result
--- @return string? err Why the exchange failed: an invalid point, or Z or V the identity
function spake2plus.verifier_finish(w0, L, y, X, Y, context, id_prover, id_verifier, opts)
  local result, detail = verifier_compute(w0, L, y, X, Y, context, id_prover, id_verifier, opts)
  if result == nil then
    return nil, tostring(detail)
  end
  return result
end

--- Whether the scalar multiplications run on OpenSSL; see `crypto.p256.is_accelerated`.
--- @return boolean accelerated
--- @return string|nil reason Why not, when not
function spake2plus.is_accelerated()
  return p256.is_accelerated()
end

-- ============================================================================
-- TEST VECTORS AND VALIDATION
-- ============================================================================

--- RFC 9383 Appendix C, the SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 vectors,
--- copied from https://www.rfc-editor.org/rfc/rfc9383.txt. The bracketed Context
--- wraps in the RFC text; the transcript's own length prefix (0x38, 56 bytes)
--- shows it ends at "Vectors".
local RFC = {
  context = "SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors",
  id_prover = "client",
  id_verifier = "server",
  w0 = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3",
  w1 = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba",
  L = "04eb7c9db3d9a9eb1f8adab81b5794c1f13ae3e225efbe91ea487425854c7fc00f"
    .. "00bfedcbd09b2400142d40a14f2064ef31dfaa903b91d1faea7093d835966efd",
  x = "d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539",
  X = "04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0c1"
    .. "de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727",
  y = "717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3",
  Y = "04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810fb"
    .. "5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048",
  Z = "04bbfce7dd7f277819c8da21544afb7964705569bdf12fb92aa388059408d50091"
    .. "a0c5f1d3127f56813b5337f9e4e67e2ca633117a4fbd559946ab474356c41839",
  V = "0458bf27c6bca011c9ce1930e8984a797a3419797b936629a5a937cf2f11c8b951"
    .. "4b82b993da8a46e664f23db7c01edc87faa530db01c2ee405230b18997f16b68",
  TT = table_concat({
    "38000000000000005350414b45322b2d503235362d5348413235362d484b4446",
    "2d5348413235362d484d41432d534841323536205465737420566563746f7273",
    "0600000000000000636c69656e74060000000000000073657276657241000000",
    "0000000004886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497",
    "333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d",
    "55a12e2d20410000000000000004d8bbd6c639c62937b04d997f38c3770719c6",
    "29d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9b",
    "d36034808cd564490b1e656edbe7410000000000000004ef3bd051bf78a2234e",
    "c0df197f7828060fe9856503579bb1733009042c15c0c1de127727f418b5966a",
    "fadfdd95a6e4591d171056b333dab97a79c7193e341727410000000000000004",
    "c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810fb",
    "5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048",
    "410000000000000004bbfce7dd7f277819c8da21544afb7964705569bdf12fb9",
    "2aa388059408d50091a0c5f1d3127f56813b5337f9e4e67e2ca633117a4fbd55",
    "9946ab474356c4183941000000000000000458bf27c6bca011c9ce1930e8984a",
    "797a3419797b936629a5a937cf2f11c8b9514b82b993da8a46e664f23db7c01e",
    "dc87faa530db01c2ee405230b18997f16b682000000000000000bb8e1bbcf3c4",
    "8f62c08db243652ae55d3e5586053fca77102994f23ad95491b3",
  }),
  K_main = "4c59e1ccf2cfb961aa31bd9434478a1089b56cd11542f53d3576fb6c2a438a29",
  K_confirmP = "871ae3f7b78445e34438fb284504240239031c39d80ac23eb5ab9be5ad6db58a",
  K_confirmV = "ccd53c7c1fa37b64a462b40db8be101cedcf838950162902054e644b400f1680",
  confirmP = "926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527",
  confirmV = "9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68",
  K_shared = "0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7",
}

--- Run the SPAKE2+ self-test: RFC 9383 Appendix C in both roles, every
--- intermediate named, then a random exchange and the failure cases.
--- @return boolean result True if all tests pass, false otherwise
function spake2plus.selftest()
  local passed = 0
  local total = 0

  --- Record one result; a function that raises counts as a failure.
  --- @param name string
  --- @param result boolean|fun(): boolean
  local function check(name, result)
    total = total + 1
    if type(result) == "function" then
      local ok, value = pcall(result)
      result = ok and value == true
      if not ok then
        print("    error: " .. tostring(value))
      end
    end
    if result == true then
      print("  ✅ PASS: " .. name)
      passed = passed + 1
    else
      print("  ❌ FAIL: " .. name)
    end
  end

  --- Compare raw bytes with expected hex, printing both when they differ.
  --- @param name string
  --- @param got string|nil
  --- @param expected_hex string
  local function check_hex(name, got, expected_hex)
    local got_hex = type(got) == "string" and bytes.to_hex(got) or tostring(got)
    check(name, got_hex == expected_hex)
    if got_hex ~= expected_hex then
      print("    expected: " .. expected_hex)
      print("    got:      " .. got_hex)
    end
  end

  local h = bytes.from_hex
  local w0, w1, x, y = h(RFC.w0), h(RFC.w1), h(RFC.x), h(RFC.y)

  print(
    "Running SPAKE2+ test vectors (RFC 9383 Appendix C, P-256, "
      .. (p256.is_accelerated() and "OpenSSL" or "pure Lua")
      .. ")..."
  )
  check("M and N match RFC 9383 section 4's compressed forms", function()
    local M, N = constants()
    return p256.equals(assert(p256.decode_point(h(M_COMPRESSED_HEX))), M)
      and p256.equals(assert(p256.decode_point(h(N_COMPRESSED_HEX))), N)
  end)

  local steps = 0
  local opts = {
    step = function()
      steps = steps + 1
    end,
  }
  check_hex("[prover] X = x*G + w0*M", spake2plus.prover_share(w0, x, opts), RFC.X)
  check("[prover] prover_share steps once", steps == 1)

  steps = 0
  local prover, prover_detail = prover_compute(w0, w1, x, h(RFC.X), h(RFC.Y), RFC.context, "client", "server", opts)
  check("[prover] finish succeeds", prover ~= nil)
  check("[prover] finish steps twice", steps == 2)
  if prover ~= nil and type(prover_detail) == "table" then
    check_hex("[prover] Z", prover_detail.Z, RFC.Z)
    check_hex("[prover] V", prover_detail.V, RFC.V)
    check_hex("[prover] TT", prover.transcript, RFC.TT)
    check_hex("[prover] K_main", prover_detail.K_main, RFC.K_main)
    check_hex("[prover] K_confirmP", prover_detail.K_confirmP, RFC.K_confirmP)
    check_hex("[prover] K_confirmV", prover_detail.K_confirmV, RFC.K_confirmV)
    check_hex("[prover] confirmP = HMAC(K_confirmP, Y)", prover.prover_confirm, RFC.confirmP)
    check_hex("[prover] confirmV = HMAC(K_confirmV, X)", prover.verifier_confirm, RFC.confirmV)
    check_hex("[prover] K_shared", prover.shared_key, RFC.K_shared)
  end

  check_hex("[verifier] L = w1*G", spake2plus.registration(w1), RFC.L)
  steps = 0
  check_hex("[verifier] Y = y*G + w0*N", spake2plus.verifier_share(w0, y, opts), RFC.Y)
  check("[verifier] verifier_share steps once", steps == 1)

  steps = 0
  local verifier, verifier_detail =
    verifier_compute(w0, h(RFC.L), y, h(RFC.X), h(RFC.Y), RFC.context, "client", "server", opts)
  check("[verifier] finish succeeds", verifier ~= nil)
  check("[verifier] finish steps twice", steps == 2)
  if verifier ~= nil and type(verifier_detail) == "table" then
    check_hex("[verifier] Z", verifier_detail.Z, RFC.Z)
    check_hex("[verifier] V", verifier_detail.V, RFC.V)
    check_hex("[verifier] TT", verifier.transcript, RFC.TT)
    check_hex("[verifier] K_main", verifier_detail.K_main, RFC.K_main)
    check_hex("[verifier] K_confirmP", verifier_detail.K_confirmP, RFC.K_confirmP)
    check_hex("[verifier] K_confirmV", verifier_detail.K_confirmV, RFC.K_confirmV)
    check_hex("[verifier] confirmP", verifier.prover_confirm, RFC.confirmP)
    check_hex("[verifier] confirmV", verifier.verifier_confirm, RFC.confirmV)
    check_hex("[verifier] K_shared", verifier.shared_key, RFC.K_shared)
  end

  print("\nRunning SPAKE2+ exchange tests...")
  local rw0 = p256.reduce(random.bytes(40))
  local rw1 = p256.reduce(random.bytes(40))
  local rx, ry = p256.random_scalar(), p256.random_scalar()
  local rX = spake2plus.prover_share(rw0, rx)
  local rY = spake2plus.verifier_share(rw0, ry)
  local rL = spake2plus.registration(rw1)
  -- The prover takes Y compressed, which must change nothing.
  local rY_compressed = p256.encode_point(assert(p256.decode_point(rY)), true)
  local p_result, p_err = spake2plus.prover_finish(rw0, rw1, rx, rX, rY_compressed, "ctx", "alice", "bob")
  local v_result, v_err = spake2plus.verifier_finish(rw0, rL, ry, rX, rY, "ctx", "alice", "bob")
  check("random exchange: both sides finish", p_result ~= nil and v_result ~= nil)
  if p_result ~= nil and v_result ~= nil then
    check("random exchange: shared keys agree", p_result.shared_key == v_result.shared_key)
    check(
      "random exchange: confirmations agree",
      p_result.prover_confirm == v_result.prover_confirm and p_result.verifier_confirm == v_result.verifier_confirm
    )
    check(
      "random exchange: transcripts agree although the prover got Y compressed",
      p_result.transcript == v_result.transcript
    )
  else
    print("    prover: " .. tostring(p_err) .. "; verifier: " .. tostring(v_err))
  end

  check("a wrong password gives different keys", function()
    local wrong = p256.reduce(string.rep("\1", 40))
    local result = spake2plus.prover_finish(wrong, rw1, rx, rX, rY, "ctx", "alice", "bob")
    return result ~= nil
      and v_result ~= nil
      and result.shared_key ~= v_result.shared_key
      and result.prover_confirm ~= v_result.prover_confirm
  end)
  check("a different context gives different keys", function()
    local result = spake2plus.prover_finish(rw0, rw1, rx, rX, rY, "other", "alice", "bob")
    return result ~= nil and v_result ~= nil and result.shared_key ~= v_result.shared_key
  end)
  check("an off-curve Y is rejected with a reason", function()
    local bad = string_sub(rY, 1, 64) .. string_char((rY:byte(65) + 1) % 256)
    local result, err = spake2plus.prover_finish(rw0, rw1, rx, rX, bad, "ctx", "alice", "bob")
    return result == nil and type(err) == "string" and err:find("invalid Y", 1, true) ~= nil
  end)
  check("an off-curve X is rejected by the verifier", function()
    local bad = string_sub(rX, 1, 64) .. string_char((rX:byte(65) + 1) % 256)
    local result, err = spake2plus.verifier_finish(rw0, rL, ry, bad, rY, "ctx", "alice", "bob")
    return result == nil and type(err) == "string" and err:find("invalid X", 1, true) ~= nil
  end)
  check("the identity encoding is rejected", function()
    return spake2plus.prover_finish(rw0, rw1, rx, rX, "\0", "ctx", "alice", "bob") == nil
  end)
  check("Y = w0*N, which makes Z and V the identity, is rejected", function()
    local _, N = constants()
    local degenerate = p256.encode_point(p256.mul(rw0, N))
    local result, err = spake2plus.prover_finish(rw0, rw1, rx, rX, degenerate, "ctx", "alice", "bob")
    return result == nil and type(err) == "string" and err:find("identity", 1, true) ~= nil
  end)
  check("nil context and identities are empty strings", function()
    local a = spake2plus.prover_finish(w0, w1, x, h(RFC.X), h(RFC.Y))
    local b = spake2plus.prover_finish(w0, w1, x, h(RFC.X), h(RFC.Y), "", "", "")
    return a ~= nil and b ~= nil and a.transcript == b.transcript and a.shared_key == b.shared_key
  end)
  check("a short scalar raises", function()
    return pcall(spake2plus.prover_share, string.rep("\1", 31), rx) == false
      and pcall(spake2plus.registration, "") == false
  end)
  check("a non-function step raises", function()
    --- @diagnostic disable-next-line: assign-type-mismatch -- the wrong type is the test
    return pcall(spake2plus.prover_share, rw0, rx, { step = 1 }) == false
  end)
  check("is_accelerated agrees with p256, reason included", function()
    local a, a_reason = spake2plus.is_accelerated()
    local b, b_reason = p256.is_accelerated()
    return a == b and a_reason == b_reason
  end)

  print(string.format("\nSPAKE2+ result: %d/%d tests passed\n", passed, total))
  return passed == total
end

--- Run performance benchmarks for SPAKE2+, both roles.
function spake2plus.benchmark()
  local h = bytes.from_hex
  local w0, w1, x, y = h(RFC.w0), h(RFC.w1), h(RFC.x), h(RFC.y)
  local X, Y, L = h(RFC.X), h(RFC.Y), h(RFC.L)

  print("SPAKE2+ P-256 (" .. (p256.is_accelerated() and "OpenSSL" or "pure Lua") .. "):")
  benchmark_op("prover_share (2 multiplications)", function()
    spake2plus.prover_share(w0, x)
  end, 3)
  benchmark_op("prover_finish (3 multiplications)", function()
    spake2plus.prover_finish(w0, w1, x, X, Y, RFC.context, RFC.id_prover, RFC.id_verifier)
  end, 3)
  benchmark_op("verifier_share (2 multiplications)", function()
    spake2plus.verifier_share(w0, y)
  end, 3)
  benchmark_op("verifier_finish (3 multiplications)", function()
    spake2plus.verifier_finish(w0, L, y, X, Y, RFC.context, RFC.id_prover, RFC.id_verifier)
  end, 3)
end

return spake2plus
