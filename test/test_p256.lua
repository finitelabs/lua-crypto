--- Tests for crypto.p256: `make test` runs them, and so does the with-tests build's selftest().

local p256 = require("crypto.p256")
local bignum = require("crypto.bignum")
local openssl_wrapper = require("crypto.openssl_wrapper")
local utils = require("crypto.utils")
local bytes = utils.bytes
local floor = math.floor
local string_find = string.find
local string_rep = string.rep
local string_sub = string.sub
local P_HEX = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
local N_HEX = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
local GX_HEX = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
local GY_HEX = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
local G2_X_HEX = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
local G2_Y_HEX = "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
local G3_X_HEX = "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c"
local G3_Y_HEX = "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"
local N_BN = p256._internal.N_BN
local to_affine = p256._internal.to_affine
local scalar_mul = p256._internal.scalar_mul
local passes_known_answers = p256._internal.passes_known_answers
local field = p256._internal.field
local pure_field = p256._internal.pure_field

local string_char = string.char

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
local function selftest()
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
  p256._internal.reset_binding_check()

  print(string.format("\nP-256 result: %d/%d tests passed\n", passed, total))
  return passed == total
end

return selftest
