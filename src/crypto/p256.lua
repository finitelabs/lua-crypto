--- @module "crypto.p256"
--- NIST P-256 (secp256r1) group arithmetic: SEC 1 point encoding, scalar
--- multiplication, point addition, and scalar helpers. It is what
--- `crypto.spake2plus` is built on; there is no ECDSA or ECDH API here.
---
--- Points
--- ------
--- Points are opaque tables made by `decode_point`, `p256.G` or the group
--- operations, and every operation refuses a table it did not make. A point
--- holds its affine coordinates as 32-byte big-endian strings, so it belongs
--- to neither arithmetic backend below and stays valid when
--- `crypto.use_openssl()` is toggled. Decoding rejects the identity,
--- coordinates >= p, and anything off y^2 = x^3 - 3x + b. P-256's cofactor is
--- 1, so a point on the curve is in the prime-order group.
---
--- Scalars
--- -------
--- A scalar is a 32-byte big-endian string. `mul` does not reduce it: callers
--- pass a value in [0, n-1], which `reduce` and `random_scalar` produce. A
--- larger value still yields (k mod n) * P.
---
--- Arithmetic
--- ----------
--- Scalar multiplication is a fixed 4-bit window over Jacobian coordinates
--- (doubling dbl-2001-b for a = -3, addition add-1998-cmo-2), written once over
--- a small field interface with two implementations:
---
--- * OpenSSL: with `crypto.use_openssl(true)`, a binding that passes
---   `Feature.BN`, and a binding that reproduces the published 2G and 3G through
---   this module's own doubling and addition, field elements are `openssl.bn`
---   handles throughout (`addmod`, `submod`, `mulmod`, `sqrmod`, `invmod`, and
---   `powmod` for square roots). They are converted only where a point enters
---   or leaves an operation. A Jacobian double-and-add over these handles took
---   53 ms per 256-bit scalar multiplication on a Control4 controller (OS 4.3,
---   lua-openssl 0.8.5, 2026-11-03). Converting to and from `crypto.bignum` per
---   field operation instead would be far slower.
--- * Pure Lua: `crypto.bignum`, inverting by Fermat's little theorem. It is the
---   correctness reference and the portability fallback. One scalar
---   multiplication takes about 30 ms under LuaJIT and 75 to 100 ms under PUC
---   Lua 5.1 to 5.5 on a desktop (Apple M1 Max, 2026-11-02). It has not been
---   timed on a controller.
---
--- `is_accelerated` says which one runs. Like the rest of this library, none of
--- it is constant time.
---
--- @usage
--- local p256 = require("crypto.p256")
--- local k = p256.random_scalar()
--- local public = p256.encode_point(p256.mul_base(k)) -- 65 bytes, 0x04 || x || y
--- local peer = assert(p256.decode_point(received)) -- nil plus a reason when invalid
--- local shared = p256.mul(k, peer)
---
--- @class crypto.p256
--- @field n string Group order, 32 big-endian bytes
--- @field G crypto.p256.Point Base point
local p256 = {}

local bignum = require("crypto.bignum")
local openssl_wrapper = require("crypto.openssl_wrapper")
local random = require("crypto.random")
local utils = require("crypto.utils")
local bytes = utils.bytes
local benchmark_op = utils.benchmark.benchmark_op

-- Local references for performance
local floor = math.floor
local string_byte = string.byte
local string_char = string.char
local string_find = string.find
local string_rep = string.rep
local string_sub = string.sub

-- ============================================================================
-- CONSTANTS
-- ============================================================================

-- Curve parameters, SEC 2 section 2.4.2 / FIPS 186-5.
local P_HEX = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
local N_HEX = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
local B_HEX = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
local GX_HEX = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
local GY_HEX = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
--- p - 2, the inversion exponent.
local P_MINUS_2_HEX = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffd"
--- (p + 1) / 4: p = 3 mod 4, so a square c has the root c^((p+1)/4).
local SQRT_EXP_HEX = "3fffffffc0000000400000000000000000000000400000000000000000000000"

-- Published multiples of G, used by the OpenSSL known-answer check and the
-- selftest (also reproduced with the openssl CLI).
local G2_X_HEX = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
local G2_Y_HEX = "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
local G3_X_HEX = "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c"
local G3_Y_HEX = "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"

local P_BN = bignum.from_hex(P_HEX)
local N_BN = bignum.from_hex(N_HEX)

-- ============================================================================
-- POINTS
-- ============================================================================

--- A point on P-256 or the identity. Opaque: make one with `decode_point` or a
--- group operation, never by hand.
--- @class crypto.p256.Point
--- @field x string? Affine x, 32 big-endian bytes; nil for the identity
--- @field y string? Affine y, 32 big-endian bytes; nil for the identity
--- @field infinity boolean? True for the identity

--- Shared by every point this module makes, and how it recognises them.
local POINT_MT = {}

--- @param x string Affine x, 32 bytes, already validated
--- @param y string Affine y, 32 bytes, already validated
--- @return crypto.p256.Point point
local function new_point(x, y)
  --- @type crypto.p256.Point
  local point = setmetatable({ x = x, y = y }, POINT_MT)
  return point
end

--- @return crypto.p256.Point identity
local function identity()
  --- @type crypto.p256.Point
  local point = setmetatable({ infinity = true }, POINT_MT)
  return point
end

--- Raise unless `point` came from this module.
--- @param point any
local function check_point(point)
  if type(point) ~= "table" or getmetatable(point) ~= POINT_MT then
    error("p256: expected a point from decode_point or a p256 operation", 3)
  end
end

--- Raise unless `scalar` is a 32-byte string.
--- @param scalar any
local function check_scalar(scalar)
  if type(scalar) ~= "string" or #scalar ~= 32 then
    error("p256: a scalar must be 32 big-endian bytes", 3)
  end
end

--- Whether 32 big-endian bytes encode a value below p.
--- @param coordinate string
--- @return boolean
local function below_p(coordinate)
  return bignum.compare(bignum.from_bytes(coordinate), P_BN) < 0
end

--- p - y for a 32-byte coordinate y in [1, p-1].
--- @param y string
--- @return string negated
local function negate_coordinate(y)
  return bignum.to_bytes(bignum.sub(P_BN, bignum.from_bytes(y)), 32)
end

-- ============================================================================
-- FIELD BACKENDS
-- ============================================================================

--- Arithmetic modulo p over an opaque element type: `crypto.bignum` values for
--- the pure-Lua backend, `openssl.bn` handles for the OpenSSL one. Every
--- element passed in is already reduced, and every element returned is.
--- @class P256Field
--- @field name string Shown by benchmarks
--- @field from_bytes fun(s: string): any 32 big-endian bytes, below p
--- @field to_bytes fun(a: any): string 32 big-endian bytes
--- @field add fun(a: any, b: any): any
--- @field sub fun(a: any, b: any): any
--- @field mul fun(a: any, b: any): any
--- @field sqr fun(a: any): any
--- @field inv fun(a: any): any Inverse of a non-zero element
--- @field sqrt fun(a: any): any a^((p+1)/4): a square root when one exists
--- @field is_zero fun(a: any): boolean
--- @field equals fun(a: any, b: any): boolean
--- @field one any
--- @field three any
--- @field b any The curve coefficient b

--- @type P256Field
local pure_field
do
  local P_MINUS_2 = bignum.from_hex(P_MINUS_2_HEX)
  local SQRT_EXP = bignum.from_hex(SQRT_EXP_HEX)
  local add, sub, compare = bignum.add, bignum.sub, bignum.compare
  local mod_mul, mod_exp = bignum.mod_mul, bignum.mod_exp
  pure_field = {
    name = "pure Lua",
    from_bytes = bignum.from_bytes,
    to_bytes = function(a)
      return bignum.to_bytes(a, 32)
    end,
    add = function(a, b)
      local sum = add(a, b)
      if compare(sum, P_BN) >= 0 then
        return sub(sum, P_BN)
      end
      return sum
    end,
    sub = function(a, b)
      if compare(a, b) >= 0 then
        return sub(a, b)
      end
      return sub(add(a, P_BN), b)
    end,
    mul = function(a, b)
      return mod_mul(a, b, P_BN)
    end,
    sqr = function(a)
      return mod_mul(a, a, P_BN)
    end,
    inv = function(a)
      return mod_exp(a, P_MINUS_2, P_BN)
    end,
    sqrt = function(a)
      return mod_exp(a, SQRT_EXP, P_BN)
    end,
    is_zero = bignum.is_zero,
    equals = bignum.equals,
    one = bignum.one(),
    three = bignum.from_number(3),
    b = bignum.from_hex(B_HEX),
  }
end

--- Build the field over a binding's `openssl.bn`. Nothing is checked here; the
--- caller runs `passes_known_answers` before trusting it.
--- @param bnlib table The openssl.bn table
--- @return P256Field field
local function bn_field(bnlib)
  local text, tohex = bnlib.text, bnlib.tohex
  local addmod, submod, mulmod, sqrmod, invmod = bnlib.addmod, bnlib.submod, bnlib.mulmod, bnlib.sqrmod, bnlib.invmod
  -- Spelled `powmod` on Control4's 0.8.5 and `mod_exp` on some other builds.
  local powmod = type(bnlib.powmod) == "function" and bnlib.powmod or bnlib.mod_exp
  local iszero, compare = bnlib.iszero, bnlib.compare
  for _, fn in ipairs({ text, tohex, addmod, submod, mulmod, sqrmod, invmod, powmod, iszero, compare }) do
    if type(fn) ~= "function" then
      error("p256: openssl.bn lacks a function this module needs")
    end
  end

  local P = text(bytes.from_hex(P_HEX))
  local SQRT_EXP = text(bytes.from_hex(SQRT_EXP_HEX))
  return {
    name = "OpenSSL bn",
    from_bytes = text,
    to_bytes = function(h)
      -- bn.tohex drops leading zeros and signs negatives with "-"; only bare
      -- hex of at most 64 digits is a reduced element.
      local hex = tohex(h)
      if type(hex) ~= "string" or string_find(hex, "^%x+$") == nil or #hex > 64 then
        error("p256: openssl bn.tohex did not return a reduced element")
      end
      return bytes.from_hex(string_rep("0", 64 - #hex) .. hex)
    end,
    add = function(a, b)
      return addmod(a, b, P)
    end,
    sub = function(a, b)
      return submod(a, b, P)
    end,
    mul = function(a, b)
      return mulmod(a, b, P)
    end,
    sqr = function(a)
      return sqrmod(a, P)
    end,
    inv = function(a)
      return invmod(a, P)
    end,
    sqrt = function(a)
      return powmod(a, SQRT_EXP, P)
    end,
    is_zero = function(a)
      local zero = iszero(a)
      return zero == true or zero == 1
    end,
    equals = function(a, b)
      return compare(a, b) == 0
    end,
    one = text("\1"),
    three = text("\3"),
    b = text(bytes.from_hex(B_HEX)),
  }
end

-- ============================================================================
-- JACOBIAN ARITHMETIC
-- ============================================================================

--- A point in Jacobian coordinates (X, Y, Z), with x = X/Z^2 and y = Y/Z^3, as
--- elements of one field. The identity is represented by nil.
--- @alias P256Jacobian { [1]: any, [2]: any, [3]: any }

--- Double a point (dbl-2001-b, a = -3).
--- @param F P256Field
--- @param P P256Jacobian?
--- @return P256Jacobian?
local function jacobian_double(F, P)
  if P == nil or F.is_zero(P[2]) then
    return nil
  end
  local X1, Y1, Z1 = P[1], P[2], P[3]
  local add, sub, mul, sqr = F.add, F.sub, F.mul, F.sqr
  local delta = sqr(Z1)
  local gamma = sqr(Y1)
  local beta = mul(X1, gamma)
  local t = mul(sub(X1, delta), add(X1, delta))
  local alpha = add(add(t, t), t)
  local beta2 = add(beta, beta)
  local beta4 = add(beta2, beta2)
  local X3 = sub(sqr(alpha), add(beta4, beta4))
  local Z3 = sub(sub(sqr(add(Y1, Z1)), gamma), delta)
  local gamma_sq = sqr(gamma)
  local gamma_sq2 = add(gamma_sq, gamma_sq)
  local gamma_sq4 = add(gamma_sq2, gamma_sq2)
  local Y3 = sub(mul(alpha, sub(beta4, X3)), add(gamma_sq4, gamma_sq4))
  return { X3, Y3, Z3 }
end

--- Add two points (add-1998-cmo-2), handling the identity and P + P.
--- @param F P256Field
--- @param P P256Jacobian?
--- @param Q P256Jacobian?
--- @return P256Jacobian?
local function jacobian_add(F, P, Q)
  if P == nil then
    return Q
  elseif Q == nil then
    return P
  end
  local X1, Y1, Z1 = P[1], P[2], P[3]
  local X2, Y2, Z2 = Q[1], Q[2], Q[3]
  local add, sub, mul, sqr = F.add, F.sub, F.mul, F.sqr
  local Z1Z1 = sqr(Z1)
  local Z2Z2 = sqr(Z2)
  local U1 = mul(X1, Z2Z2)
  local U2 = mul(X2, Z1Z1)
  local S1 = mul(mul(Y1, Z2), Z2Z2)
  local S2 = mul(mul(Y2, Z1), Z1Z1)
  local H = sub(U2, U1)
  local r = sub(S2, S1)
  if F.is_zero(H) then
    if F.is_zero(r) then
      return jacobian_double(F, P)
    end
    return nil
  end
  local HH = sqr(H)
  local HHH = mul(H, HH)
  local V = mul(U1, HH)
  local X3 = sub(sub(sqr(r), HHH), add(V, V))
  local Y3 = sub(mul(r, sub(V, X3)), mul(S1, HHH))
  local Z3 = mul(mul(Z1, Z2), H)
  return { X3, Y3, Z3 }
end

--- Lift an affine point into Jacobian coordinates (Z = 1).
--- @param F P256Field
--- @param point crypto.p256.Point
--- @return P256Jacobian?
local function to_jacobian(F, point)
  if point.infinity then
    return nil
  end
  return { F.from_bytes(point.x), F.from_bytes(point.y), F.one }
end

--- Normalise a Jacobian point back to an affine one; one field inversion.
--- @param F P256Field
--- @param P P256Jacobian?
--- @return crypto.p256.Point point
local function to_affine(F, P)
  if P == nil or F.is_zero(P[3]) then
    return identity()
  end
  local z_inv = F.inv(P[3])
  local z_inv2 = F.sqr(z_inv)
  local x = F.mul(P[1], z_inv2)
  local y = F.mul(P[2], F.mul(z_inv2, z_inv))
  return new_point(F.to_bytes(x), F.to_bytes(y))
end

--- k * P with a fixed 4-bit window, most significant nibble first.
--- @param F P256Field
--- @param scalar string 32 big-endian bytes
--- @param point crypto.p256.Point
--- @return P256Jacobian?
local function scalar_mul(F, scalar, point)
  local base = to_jacobian(F, point)
  if base == nil then
    return nil
  end
  local window = { base, jacobian_double(F, base) }
  for i = 3, 15 do
    window[i] = jacobian_add(F, window[i - 1], base)
  end

  local acc = nil
  for i = 1, 32 do
    local byte = string_byte(scalar, i)
    local high = floor(byte / 16)
    local low = byte % 16
    -- Doubling the identity is the identity, so skip it until the first digit.
    if acc ~= nil then
      acc = jacobian_double(F, jacobian_double(F, jacobian_double(F, jacobian_double(F, acc))))
    end
    if high ~= 0 then
      acc = jacobian_add(F, acc, window[high])
    end
    if acc ~= nil then
      acc = jacobian_double(F, jacobian_double(F, jacobian_double(F, jacobian_double(F, acc))))
    end
    if low ~= 0 then
      acc = jacobian_add(F, acc, window[low])
    end
  end
  return acc
end

--- x^3 - 3x + b, the right-hand side of the curve equation.
--- @param F P256Field
--- @param x any Field element
--- @return any rhs
local function curve_rhs(F, x)
  return F.add(F.mul(F.sub(F.sqr(x), F.three), x), F.b)
end

-- ============================================================================
-- BACKEND SELECTION
-- ============================================================================

--- Whether a field reproduces the published 2G and 3G through this module's own
--- doubling, addition and normalisation, and recovers Gy as a square root.
--- Exercises every field operation the scalar multiplication uses.
--- @param F P256Field
--- @return boolean passed
local function passes_known_answers(F)
  local ok, passed = pcall(function()
    local G = to_jacobian(F, new_point(bytes.from_hex(GX_HEX), bytes.from_hex(GY_HEX)))
    local two = to_affine(F, jacobian_double(F, G))
    local three = to_affine(F, jacobian_add(F, jacobian_double(F, G), G))
    local root = F.to_bytes(F.sqrt(curve_rhs(F, F.from_bytes(bytes.from_hex(GX_HEX)))))
    local gy = bytes.from_hex(GY_HEX)
    return two.x == bytes.from_hex(G2_X_HEX)
      and two.y == bytes.from_hex(G2_Y_HEX)
      and three.x == bytes.from_hex(G3_X_HEX)
      and three.y == bytes.from_hex(G3_Y_HEX)
      and (root == gy or root == negate_coordinate(gy))
  end)
  return ok and passed == true
end

--- The binding the OpenSSL field was last checked against, and the verdict.
--- @type table?
local _checked_binding = nil
--- @type P256Field|false
local _bn_field = false

--- The OpenSSL field if acceleration is on and the binding is trusted, else nil.
--- @return P256Field?
local function trusted_bn_field()
  local openssl = openssl_wrapper.get(openssl_wrapper.Feature.BN)
  if openssl == nil then
    return nil
  end
  if _checked_binding ~= openssl then
    _checked_binding = openssl
    local ok, field = pcall(bn_field, openssl.bn)
    _bn_field = ok and passes_known_answers(field) and field or false
  end
  return _bn_field or nil
end

--- The field every operation runs on right now.
--- @return P256Field
local function field()
  return trusted_bn_field() or pure_field
end

-- ============================================================================
-- PUBLIC INTERFACE
-- ============================================================================

--- The group order n, 32 big-endian bytes.
p256.n = bytes.from_hex(N_HEX)

--- The base point G.
p256.G = new_point(bytes.from_hex(GX_HEX), bytes.from_hex(GY_HEX))

--- Decode a SEC 1 point and check it.
---
--- Accepts uncompressed (65 bytes, 0x04 || x || y) and compressed (33 bytes,
--- 0x02 or 0x03 || x) encodings. Rejects the identity, coordinates >= p and
--- points off the curve, returning nil and a reason rather than raising, since
--- the input is normally a peer's.
---
--- @param encoded string SEC 1 encoding
--- @return crypto.p256.Point? point The point, or nil when invalid
--- @return string? err Why it is invalid
function p256.decode_point(encoded)
  if type(encoded) ~= "string" then
    return nil, "p256: a point must be a byte string"
  end
  local prefix = string_byte(encoded, 1)
  if #encoded == 1 and prefix == 0 then
    return nil, "p256: the identity is not accepted as a point"
  end
  local x, y
  if #encoded == 65 and prefix == 4 then
    x, y = string_sub(encoded, 2, 33), string_sub(encoded, 34, 65)
  elseif #encoded == 33 and (prefix == 2 or prefix == 3) then
    x = string_sub(encoded, 2, 33)
  else
    return nil, "p256: expected a 65-byte uncompressed (0x04) or 33-byte compressed (0x02, 0x03) SEC 1 point"
  end
  if not below_p(x) or (y ~= nil and not below_p(y)) then
    return nil, "p256: a coordinate is not below the field prime"
  end

  local F = field()
  local rhs = curve_rhs(F, F.from_bytes(x))
  if y ~= nil then
    if not F.equals(F.sqr(F.from_bytes(y)), rhs) then
      return nil, "p256: the point is not on the curve"
    end
    return new_point(x, y)
  end

  local root = F.sqrt(rhs)
  if not F.equals(F.sqr(root), rhs) then
    return nil, "p256: x is not the coordinate of a point on the curve"
  end
  y = F.to_bytes(root)
  if (string_byte(y, 32) % 2 == 1) ~= (prefix == 3) then
    -- Never zero on P-256 (there is no point of order 2), but say so if it were.
    if F.is_zero(root) then
      return nil, "p256: x is not the coordinate of a point with that parity"
    end
    y = negate_coordinate(y)
  end
  return new_point(x, y)
end

--- Encode a point in SEC 1 form. Raises on the identity, which has no
--- encoding a peer would accept.
--- @param point crypto.p256.Point
--- @param compressed? boolean True for 33 bytes, otherwise 65
--- @return string encoded
function p256.encode_point(point, compressed)
  check_point(point)
  if point.infinity then
    error("p256: the identity has no SEC 1 encoding here", 2)
  end
  local x, y = point.x, point.y
  --- @cast x string
  --- @cast y string
  if compressed then
    return (string_byte(y, 32) % 2 == 1 and "\3" or "\2") .. x
  end
  return "\4" .. x .. y
end

--- Scalar multiplication, k * P.
--- @param scalar string 32 big-endian bytes, in [0, n-1]
--- @param point crypto.p256.Point
--- @return crypto.p256.Point product
function p256.mul(scalar, point)
  check_scalar(scalar)
  check_point(point)
  local F = field()
  return to_affine(F, scalar_mul(F, scalar, point))
end

--- Scalar multiplication of the base point, k * G.
--- @param scalar string 32 big-endian bytes, in [0, n-1]
--- @return crypto.p256.Point product
function p256.mul_base(scalar)
  check_scalar(scalar)
  local F = field()
  return to_affine(F, scalar_mul(F, scalar, p256.G))
end

--- Point addition, P + Q.
--- @param p crypto.p256.Point
--- @param q crypto.p256.Point
--- @return crypto.p256.Point sum
function p256.add(p, q)
  check_point(p)
  check_point(q)
  if p.infinity then
    return q
  elseif q.infinity then
    return p
  end
  local F = field()
  return to_affine(F, jacobian_add(F, to_jacobian(F, p), to_jacobian(F, q)))
end

--- Point subtraction, P - Q.
--- @param p crypto.p256.Point
--- @param q crypto.p256.Point
--- @return crypto.p256.Point difference
function p256.sub(p, q)
  check_point(p)
  check_point(q)
  if q.infinity then
    return p
  end
  local qy = q.y
  --- @cast qy string
  return p256.add(p, new_point(q.x, negate_coordinate(qy)))
end

--- Whether a point is the identity.
--- @param point crypto.p256.Point
--- @return boolean
function p256.is_identity(point)
  check_point(point)
  return point.infinity == true
end

--- Whether two points are equal.
--- @param p crypto.p256.Point
--- @param q crypto.p256.Point
--- @return boolean
function p256.equals(p, q)
  check_point(p)
  check_point(q)
  if p.infinity or q.infinity then
    return p.infinity == true and q.infinity == true
  end
  return p.x == q.x and p.y == q.y
end

--- Reduce a big-endian integer of any length modulo n.
---
--- RFC 9383 derives w0 and w1 by reducing PBKDF output halves at least 64 bits
--- longer than n, which keeps the bias below 2^-64; this is that reduction.
--- @param value string Big-endian bytes, any length ("" is zero)
--- @return string scalar 32 big-endian bytes, in [0, n-1]
function p256.reduce(value)
  assert(type(value) == "string", "p256: reduce takes a byte string")
  return bignum.to_bytes(bignum.mod(bignum.from_bytes(value), N_BN), 32)
end

--- A uniformly random scalar in [1, n-1] from `crypto.random`.
---
--- Draws 32 bytes and redraws when the value is 0 or >= n, which happens with
--- probability about 2^-32, so the result is exactly uniform.
--- @return string scalar 32 big-endian bytes
function p256.random_scalar()
  while true do
    local candidate = random.bytes(32)
    local value = bignum.from_bytes(candidate)
    if not bignum.is_zero(value) and bignum.compare(value, N_BN) < 0 then
      return candidate
    end
  end
end

--- Whether scalar multiplication runs on OpenSSL.
---
--- True only when acceleration is enabled, the binding passes `Feature.BN`, and
--- it reproduces the published 2G and 3G through this module's own doubling and
--- addition -- the same conditions the operations apply. When false, the
--- second value says why, in the same terms as `crypto.bignum.is_accelerated`:
--- a driver that never called `crypto.use_openssl(true)` and a host that cannot
--- accelerate both read false, and need opposite fixes.
---
--- @return boolean accelerated
--- @return string|nil reason Why not, when not
function p256.is_accelerated()
  local openssl = openssl_wrapper.get(openssl_wrapper.Feature.BN)
  if openssl == nil then
    return false,
      openssl_wrapper.unavailable_reason(openssl_wrapper.Feature.BN) or "OpenSSL P-256 field arithmetic is unavailable"
  end
  if trusted_bn_field() == nil then
    return false,
      "the lua-openssl binding failed p256's 2G/3G known-answer check, so its field arithmetic is not trusted"
  end
  return true
end

-- ============================================================================
-- TEST VECTORS AND VALIDATION
-- ============================================================================

-- Multiples of G as uncompressed points, hex. 2G and 3G are the published
-- values above. The RFC 6979 A.2.5 key pair is published there too. The rest
-- were derived with the openssl CLI (OpenSSL 4.1.0): a DER EC key built with
-- `openssl asn1parse -genconf` from the chosen private scalar, whose public
-- point `openssl ec -text` then computes and prints.
local RFC6979_D = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
local RFC6979_U = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
  .. "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
local MULTIPLES = {
  { name = "2G (published)", k = string_rep("0", 63) .. "2", point = "04" .. G2_X_HEX .. G2_Y_HEX },
  { name = "3G (published)", k = string_rep("0", 63) .. "3", point = "04" .. G3_X_HEX .. G3_Y_HEX },
  { name = "RFC 6979 A.2.5 key pair", k = RFC6979_D, point = RFC6979_U },
  {
    name = "(n-1)G = -G (openssl CLI)",
    k = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
    point = "04" .. GX_HEX .. "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
  },
  {
    name = "(2^128 - 1)G, leading zero bytes (openssl CLI)",
    k = "00000000000000000000000000000000ffffffffffffffffffffffffffffffff",
    point = "04faa31e824f8143caeb2b0e68deee70bd45dc5b9a78fa0741ee22a6a7b9d0b22f"
      .. "e6078b5a598df8b65ba3d288e70db604a25d90279d586d11282d704f8bd18f2d",
  },
  {
    name = "(2^255)G, zero nibbles throughout (openssl CLI)",
    k = "8000000000000000000000000000000000000000000000000000000000000000",
    point = "0477b20a912e6b23135066e911891524bc4efe3560e3e92350b52dec8f375f2b54"
      .. "a3dc291825cea3f7f7b10bfcdd038a72df623da1e850e0f1caa801fcd6cc67ff",
  },
}
-- s * U for the RFC 6979 public key U, derived with the openssl CLI as
-- (s * d mod n) * G, and U + G and U - G as (d + 1) * G and (d - 1) * G.
local S_SCALAR = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
local S_TIMES_U = "04785884d61b6393c6e92bb48fba4d351493bb11d45cf70aafc59b29ba21c3c653"
  .. "b49783b112d1838f82748c84a4df87063a663e0934259216b3a4931faacc6eb5"
local U_PLUS_G = "0415797ae57c574afdcfcd1fe48482512bf8134a0338f14e0374a542585477fd70"
  .. "296a96b3f5cf14e63952aa745f9249d3d5d5d8db94651a93070f53513dc15271"
local U_MINUS_G = "04477dfe26ed0d54e7164a1116f73ca42741c17029ec37b39e6167365d142c4ac9"
  .. "9a827ce950d360890f8e3571d105e27c18a0f725ba43c2b4485e67e8532214fd"
-- Compressed encodings printed by `openssl ec -conv_form compressed`.
local COMPRESSED = {
  { name = "G", compressed = "03" .. GX_HEX, point = "04" .. GX_HEX .. GY_HEX },
  { name = "3G (even y)", compressed = "02" .. G3_X_HEX, point = "04" .. G3_X_HEX .. G3_Y_HEX },
  {
    name = "RFC 6979 U",
    compressed = "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
    point = RFC6979_U,
  },
}

--- A stand-in `openssl.bn` over `crypto.bignum`, shaped like lua-openssl's:
--- `text` takes big-endian bytes, `tohex` gives uppercase hex without leading
--- zero bytes, handles are opaque. Its arithmetic avoids `bignum.mod_exp`, which
--- would route back into the stand-in while bignum is still checking it.
--- @param fault string|nil "sqrmod" answers squares off by one
--- @return table binding
local function stand_in_binding(fault)
  local function wrap(value)
    return { value = value }
  end
  local function reduce(value, m)
    return bignum.mod(value, m.value)
  end
  local function pow(base, exponent, m)
    local result = { 1 }
    local b = reduce(base.value, m)
    for i = bignum.bit_length(exponent.value) - 1, 0, -1 do
      result = reduce(bignum.mul(result, result), m)
      local limb = exponent.value[floor(i / 24) + 1]
      if floor(limb / 2 ^ (i % 24)) % 2 == 1 then
        result = reduce(bignum.mul(result, b), m)
      end
    end
    return wrap(result)
  end
  local bn = {
    text = function(raw)
      return wrap(bignum.from_bytes(raw))
    end,
    tohex = function(h)
      local hex = bignum.to_hex(h.value)
      if #hex % 2 == 1 and hex ~= "0" then
        hex = "0" .. hex
      end
      return hex:upper()
    end,
    addmod = function(a, b, m)
      return wrap(reduce(bignum.add(a.value, b.value), m))
    end,
    submod = function(a, b, m)
      return wrap(bignum.mod_sub(a.value, b.value, m.value))
    end,
    mulmod = function(a, b, m)
      return wrap(reduce(bignum.mul(a.value, b.value), m))
    end,
    sqrmod = function(a, m)
      local square = reduce(bignum.mul(a.value, a.value), m)
      if fault == "sqrmod" then
        square = bignum.add(square, { 1 })
      end
      return wrap(square)
    end,
    invmod = function(a, m)
      return pow(a, wrap(bignum.sub(m.value, { 2 })), m)
    end,
    powmod = pow,
    iszero = function(a)
      return bignum.is_zero(a.value)
    end,
    compare = function(a, b)
      return bignum.compare(a.value, b.value)
    end,
  }
  return {
    version = function()
      return "0.8.5"
    end,
    bn = bn,
  }
end

--- Run the P-256 self-test.
---
--- Every multiplication vector runs on whichever field is active and, when
--- OpenSSL is, on the pure-Lua one as well, so an accelerated host checks both.
--- A stand-in binding then drives the OpenSSL field on hosts without one.
--- @return boolean result True if all tests pass, false otherwise
function p256.selftest()
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

  local function point(hex)
    return assert(p256.decode_point(bytes.from_hex(hex)))
  end
  local function hex_of(p)
    return bytes.to_hex(p256.encode_point(p))
  end

  local active = field()
  local fields = { active }
  if active ~= pure_field then
    fields[2] = pure_field
  end

  print("Running P-256 test vectors (" .. active.name .. ")...")
  check("G encodes to the SEC 2 base point", hex_of(p256.G) == "04" .. GX_HEX .. GY_HEX)
  check("n is the SEC 2 group order", bytes.to_hex(p256.n) == N_HEX)
  for _, F in ipairs(fields) do
    local suffix = " [" .. F.name .. "]"
    for _, vector in ipairs(MULTIPLES) do
      check(vector.name .. suffix, function()
        return bytes.to_hex(p256.encode_point(to_affine(F, scalar_mul(F, bytes.from_hex(vector.k), p256.G))))
          == vector.point
      end)
    end
    check("s * U, an arbitrary point (openssl CLI)" .. suffix, function()
      local product = to_affine(F, scalar_mul(F, bytes.from_hex(S_SCALAR), point(RFC6979_U)))
      return hex_of(product) == S_TIMES_U
    end)
    check("known answers pass" .. suffix, passes_known_answers(F))
  end

  check("mul_base agrees with mul(k, G)", function()
    local k = bytes.from_hex(RFC6979_D)
    return p256.equals(p256.mul_base(k), p256.mul(k, p256.G)) and hex_of(p256.mul_base(k)) == RFC6979_U
  end)
  check("U + G = (d + 1)G (openssl CLI)", hex_of(p256.add(point(RFC6979_U), p256.G)) == U_PLUS_G)
  check("U - G = (d - 1)G (openssl CLI)", hex_of(p256.sub(point(RFC6979_U), p256.G)) == U_MINUS_G)
  check("G + G doubles to 2G", hex_of(p256.add(p256.G, p256.G)) == "04" .. G2_X_HEX .. G2_Y_HEX)
  check("2G + G = 3G", hex_of(p256.add(point("04" .. G2_X_HEX .. G2_Y_HEX), p256.G)) == "04" .. G3_X_HEX .. G3_Y_HEX)

  print("\nRunning P-256 identity tests...")
  local zero = string_rep("\0", 32)
  check("0 * G is the identity", p256.is_identity(p256.mul_base(zero)))
  check("n * G is the identity", p256.is_identity(p256.mul_base(p256.n)))
  check("k * identity is the identity", function()
    return p256.is_identity(p256.mul(bytes.from_hex(RFC6979_D), p256.sub(p256.G, p256.G)))
  end)
  check("G - G is the identity", p256.is_identity(p256.sub(p256.G, p256.G)))
  check("G + (-G) is the identity", function()
    local minus_g = p256.mul_base(bytes.from_hex(MULTIPLES[4].k))
    return p256.is_identity(p256.add(p256.G, minus_g))
  end)
  check("identity + G = G and G + identity = G", function()
    local id = p256.sub(p256.G, p256.G)
    return p256.equals(p256.add(id, p256.G), p256.G) and p256.equals(p256.add(p256.G, id), p256.G)
  end)
  check("equals: identity only equals the identity", function()
    local id = p256.mul_base(zero)
    return p256.equals(id, p256.sub(p256.G, p256.G)) and not p256.equals(id, p256.G) and not p256.equals(p256.G, id)
  end)
  check("encoding the identity raises", pcall(p256.encode_point, p256.mul_base(zero)) == false)

  print("\nRunning P-256 encoding tests...")
  for _, vector in ipairs(COMPRESSED) do
    check("compressed " .. vector.name .. " decodes", function()
      return hex_of(point(vector.compressed)) == vector.point
    end)
    check("compressed " .. vector.name .. " encodes", function()
      return bytes.to_hex(p256.encode_point(point(vector.point), true)) == vector.compressed
    end)
  end
  --- @param hex string
  --- @return boolean rejected
  local function rejected(hex)
    local decoded, err = p256.decode_point(bytes.from_hex(hex))
    return decoded == nil and type(err) == "string"
  end
  local g_y_plus_one = bignum.to_bytes(bignum.add(bignum.from_hex(GY_HEX), { 1 }), 32)
  check("rejects the identity encoding", rejected("00"))
  check("rejects an empty string", rejected(""))
  check("rejects a bad prefix", rejected("05" .. GX_HEX .. GY_HEX))
  check("rejects a compressed prefix on 65 bytes", rejected("02" .. GX_HEX .. GY_HEX))
  check("rejects an uncompressed prefix on 33 bytes", rejected("04" .. GX_HEX))
  check("rejects a truncated point", rejected("04" .. GX_HEX .. string_sub(GY_HEX, 1, 62)))
  check("rejects x = p", rejected("04" .. P_HEX .. GY_HEX))
  check("rejects y = p", rejected("04" .. GX_HEX .. P_HEX))
  check("rejects compressed x = p", rejected("02" .. P_HEX))
  check("rejects a point off the curve", rejected("04" .. GX_HEX .. bytes.to_hex(g_y_plus_one)))
  -- 1 - 3 + b is not a square mod p (checked with CPython's pow).
  check("rejects a compressed x with no point", rejected("02" .. string_rep("0", 63) .. "1"))
  check("rejects a non-string", function()
    --- @diagnostic disable-next-line: param-type-mismatch -- the wrong type is the test
    return p256.decode_point(42) == nil
  end)

  print("\nRunning P-256 scalar tests...")
  check("reduce(n) is zero", p256.reduce(p256.n) == zero)
  check('reduce("") is zero', p256.reduce("") == zero)
  check(
    "reduce leaves a 32-byte value below n alone",
    p256.reduce(bytes.from_hex(RFC6979_D)) == bytes.from_hex(RFC6979_D)
  )
  check("reduce(n + 1) is one", function()
    return p256.reduce(bignum.to_bytes(bignum.add(N_BN, { 1 }))) == string_rep("\0", 31) .. "\1"
  end)
  -- 40-byte inputs, the RFC 9383 w0/w1 shape; expected values from CPython.
  check("reduce of 40 bytes 01..28", function()
    local input = {}
    for i = 1, 40 do
      input[i] = string_char(i)
    end
    return bytes.to_hex(p256.reduce(table.concat(input)))
      == "0e101214070605041155b315cb1c6f28abec21cff529b6e3d3e045e760833d5c"
  end)
  check("reduce of 40 bytes of 0xff", function()
    return bytes.to_hex(p256.reduce(string_rep("\255", 40)))
      == "fffffffe00000001431905529c0166cd22159165b6faae70f756a571fc632550"
  end)
  check("random_scalar is in [1, n-1] and fresh", function()
    local a, b = p256.random_scalar(), p256.random_scalar()
    local value = bignum.from_bytes(a)
    return #a == 32 and a ~= b and not bignum.is_zero(value) and bignum.compare(value, N_BN) < 0
  end)
  check("a 31-byte scalar raises", pcall(p256.mul_base, string_rep("\1", 31)) == false)
  check("a hand-made point raises", function()
    --- @diagnostic disable-next-line: param-type-mismatch -- the wrong type is the test
    return pcall(p256.mul, bytes.from_hex(RFC6979_D), { x = string_rep("\1", 32), y = string_rep("\1", 32) }) == false
  end)
  check("is_accelerated returns a boolean and, when false, a reason", function()
    local accelerated, reason = p256.is_accelerated()
    return type(accelerated) == "boolean" and (accelerated or type(reason) == "string")
  end)

  print("\nRunning P-256 OpenSSL field against a stand-in binding...")
  local saved_use = openssl_wrapper.enabled()
  local saved_loaded = package.loaded["openssl"]
  local saved_preload = package.preload["openssl"]
  --- @param binding table|nil
  local function install(binding)
    package.loaded["openssl"] = binding
    package.preload["openssl"] = nil
    openssl_wrapper.use(true)
  end

  install(stand_in_binding())
  check("stand-in binding is trusted", p256.is_accelerated() == true)
  check("stand-in: field is the OpenSSL one", field().name == "OpenSSL bn")
  check("stand-in: RFC 6979 key pair", function()
    return hex_of(p256.mul_base(bytes.from_hex(RFC6979_D))) == RFC6979_U
  end)
  check("stand-in: s * U", hex_of(p256.mul(bytes.from_hex(S_SCALAR), point(RFC6979_U))) == S_TIMES_U)
  check("stand-in: compressed decode", function()
    return hex_of(point(COMPRESSED[3].compressed)) == RFC6979_U
      and hex_of(point(COMPRESSED[2].compressed)) == "04" .. G3_X_HEX .. G3_Y_HEX
  end)
  check("stand-in: off-curve point rejected", rejected("04" .. GX_HEX .. bytes.to_hex(g_y_plus_one)))

  install(stand_in_binding("sqrmod"))
  check("a binding with a wrong sqrmod is declined", function()
    local accelerated, reason = p256.is_accelerated()
    return accelerated == false and type(reason) == "string" and string_find(reason, "known-answer", 1, true) ~= nil
  end)
  check("declined binding: results still correct", hex_of(p256.mul_base(bytes.from_hex(RFC6979_D))) == RFC6979_U)

  package.loaded["openssl"] = saved_loaded
  package.preload["openssl"] = saved_preload
  openssl_wrapper.use(saved_use)
  _checked_binding = nil
  _bn_field = false

  print(string.format("\nP-256 result: %d/%d tests passed\n", passed, total))
  return passed == total
end

--- Run performance benchmarks for P-256.
function p256.benchmark()
  local k = bytes.from_hex(RFC6979_D)
  local u = assert(p256.decode_point(bytes.from_hex(RFC6979_U)))
  local compressed = bytes.from_hex(COMPRESSED[3].compressed)
  local uncompressed = bytes.from_hex(RFC6979_U)

  print("P-256 (" .. field().name .. "):")
  benchmark_op("mul_base", function()
    p256.mul_base(k)
  end, 5)
  benchmark_op("mul (arbitrary point)", function()
    p256.mul(k, u)
  end, 5)
  benchmark_op("add", function()
    p256.add(u, p256.G)
  end, 50)
  benchmark_op("decode_point (compressed)", function()
    p256.decode_point(compressed)
  end, 20)
  benchmark_op("decode_point (uncompressed)", function()
    p256.decode_point(uncompressed)
  end, 50)
end

return p256
