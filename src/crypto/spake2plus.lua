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
local sha256 = require("crypto.sha256")
local utils = require("crypto.utils")
local bytes = utils.bytes

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
-- these by the tests.
local M_HEX = "04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
  .. "5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20"
local N_HEX = "04d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
  .. "07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7"

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

--- Intermediate values, for the tests.
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

-- Private functions and values the tests in test/ check directly.
spake2plus._internal = {
  constants = constants,
  prover_compute = prover_compute,
  verifier_compute = verifier_compute,
}

return spake2plus
