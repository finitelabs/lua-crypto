--- Tests for crypto.bignum: `make test` runs them, and so does the with-tests build's selftest().

local bignum = require("crypto.bignum")
local openssl_wrapper = require("crypto.openssl_wrapper")
local string_format = string.format
local string_rep = string.rep
local table_concat = table.concat
local VEC_X_HEX = "f0e1d2c3b4a5968778695a4b3c2d1e0fdeadbeefcafebabe0123456789abcdef"
local VEC_Y_HEX = "fedcba987654321fedcba9876543210abcdef0123456789"
local VEC_M_HEX = "fffffffffffffffffffffffffffffffeffffffffffffffff"
local VEC_MUL_HEX = table_concat({
  "efcfc0c2d5fa2f84db52db751fdba8927fd0cfb89d03a6e23469667bcbb09e04",
  "0c96803be0e492284a6a2290002002425d85431fb375de7",
})
local VEC_QUO_HEX = "f1f51dfdb8e1c16d7"
local VEC_REM_HEX = "4e56a81e2677fc8622ba2a844cc25a8440c2e32a28013e0"
local VEC_MOD_X_HEX = "78695a4b3c2d1e10cf8f91b37fa45145f205182b3e516476"
local VEC_MOD_MUL_HEX = "c5789ec2c73be1123b996b5bf34a44eba5d1145d374fc548"
local VEC_MOD_EXP_HEX = "e6663770f70809f8c052b35cc00534b8d5b2c013a9d4874c"
local add_raw = bignum._internal.add_raw
local mul_raw = bignum._internal.mul_raw
local divmod_raw = bignum._internal.divmod_raw
local mod_exp_montgomery = bignum._internal.mod_exp_montgomery
local mod_exp_reference = bignum._internal.mod_exp_reference

local utils = require("crypto.utils")

local bytes = utils.bytes

local string_upper = string.upper

local VEC_ADD_HEX = "f0e1d2c3b4a59687885725f4c3926131dd8a79884152ecceacf13468acf13578"

local VEC_SUB_HEX = "f0e1d2c3b4a59687687b8ea1b4c7daeddfd1045754aa88ad5555566666666666"

local VEC_MOD_ADD_HEX = "885725f4c3926132ce6c4c4bf5f883569dd3072c6196cbff"

local VEC_MOD_SUB_HEX = "9784715e4b3825112f4d28e4f6afe0c9b9c8d6d5e4f40312"

--- RFC 5054 Appendix A / RFC 3526 group 15: the 3072-bit safe prime N.
--- Its generator is g = 5.
-- Every expected value below was produced independently with CPython's
-- arbitrary-precision integers (`python3 -c "print(pow(g, x, N))"` and friends)
-- and committed here as a literal.
local RFC5054_N_HEX = table.concat({
  "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74",
  "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437",
  "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed",
  "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05",
  "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb",
  "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b",
  "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718",
  "3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33",
  "a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7",
  "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864",
  "d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2",
  "08e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff",
})

local SRP_EXP_A_HEX = "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393"

local SRP_RESULT_A_HEX = table.concat({
  "fab6f5d2615d1e323512e7991cc37443f487da604ca8c9230fcb04e541dce628",
  "0b27ca4680b0374f179dc3bdc7553fe62459798c701ad864a91390a28c93b644",
  "adbf9c00745b942b79f9012a21b9b78782319d83a1f8362866fbd6f46bfc0ddb",
  "2e1ab6e4b45a9906b82e37f05d6f97f6a3eb6e182079759c4f6847837b62321a",
  "c1b4fa68641fcb4bb98dd697a0c73641385f4bab25b793584cc39fc8d48d4bd8",
  "67a9a3c10f8ea12170268e34fe3bbe6ff89998d60da2f3e4283cbec1393d52af",
  "724a57230c604e9fbce583d7613e6bffd67596ad121a8707eec4694495703368",
  "6a155f644d5c5863b48f61bdbf19a53eab6dad0a186b8c152e5f5d8cad4b0ef8",
  "aa4ea5008834c3cd342e5e0f167ad04592cd8bd279639398ef9e114dfaaab919",
  "e14e850989224ddd98576d79385d2210902e9f9b1f2d86cfa47ee244635465f7",
  "1058421a0184be51dd10cc9d079e6f1604e7aa9b7cf7883c7d4ce12b06ebe160",
  "81e23f27a231d18432d7d1bb55c28ae21ffcf005f57528d15a88881bb3bbb7fe",
})

local SRP_EXP_B_HEX = table.concat({
  "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
  "3fbb0e0e1e0b1a1c9d8e7f60514243342a1b0c9f8e7d6c5b4a39281706f5e4d3",
  "c2b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a3928170615243f",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a39281706152433",
  "42b1a09f8e7d6c5b4a3928170615243342b1a09f8e7d6c5b4a3928170615243f",
})

local SRP_RESULT_B_HEX = table.concat({
  "1e9606e73774d51f84e1eefb8e8ce7b07a0e204b76dc57d55968d4159a32f760",
  "4e36da94747fc9f995e920741169aa810cc25e4a4b7df654bb8e48275e063d6c",
  "744f1e3bfcd18b84e97a69d39ac775b466cc1b0928f0ee55d79e05329a942ca6",
  "af50f660d4af6129e9e378119843836ea8b7c0aa1035d6e33ebf3defd0512ebf",
  "c6dbb3e111a8630cf6d444e98e23fd5219747dcc537da5742fe3b3262a61e6b4",
  "6fa328d398d104bc3735f5e0f883b4c8fe1b3ee5b77ba2222b9b4cff974e060d",
  "9b52bc56a4edaf6b88a149b06eace7a40f68348fd84a28c95a524da2846cd738",
  "4ce58188f44f27c279b5e1279754d82794a67db88ed67a44eddb189094f7830d",
  "4748cecd898d44387558e41293561752775c44360fc5b57fa386470b2019da88",
  "0637a5443c2165f23b2f914b33b601edc8e2aff5dd916387e4c186d495a790da",
  "5f4b2e82b2a881479a4c819086e5fd284fe5144c2cc259d7b5c5c085430268ea",
  "664826f9fdb4e4183b8613b772c50a56a97f1a13c0471d562151b41fcfbd3559",
})

local SRP_BASE_OVER_N_HEX = table.concat({
  "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74",
  "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437",
  "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed",
  "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05",
  "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb",
  "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b",
  "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718",
  "3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33",
  "a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7",
  "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864",
  "d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2",
  "08e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2cb0000000000000006",
})

local SRP_RESULT_OVER_HEX = table.concat({
  "34fd4d3beb508957d7a1b34394835595739fcebae187bc7cf18d8dbee1f8cdd7",
  "fbb20f4d870b7f9f9d13dad25006445975cf81c4fffa0bd26bb399c2b235657c",
  "a7aae7ac6bc6a78cba6ddfd1cc971505b6acbdbbadf8c8346006590588209cbe",
  "3b21c7141166f53da71b9d739c785aa1c722ff5ad6bf0d8556e1836570c3e62d",
  "b1fe8c715b84867c31faa7621b315130de124f38b250052217658a2535e0ca89",
  "014101aec9e8ca705a37b8956dc5a629f80a542c4f02e01150ddd44228c76ab6",
  "77e930f3875e57c5cf87a3ac3b16f94ed2427aa5c4028cb5b7dfd568057f1285",
  "46a28a0cdbf79120c2a955956c7f4ad6220929ae1f76954d347de3bd57d05e31",
  "ca711fa27ab77fc85473d4ba7e89dcca338a0e5c06009edeb5788cc9bc840add",
  "6f3f740da521f6b3be5a1ac0e4d1b8acb500ebe95c99cf713b972ee1f6e4bf29",
  "af7c5f4b88d5893f2deab5df5cb6e7e3ab516d388a9bcdfda0867b6bc93197b9",
  "519e5b25ffa39abb52b18dc6e7e78f601443ae575f1bc59ffc2d86a06af4cf04",
})

local CROSS_CHECK_VECTORS = {
  {
    base = "502d7ab70ebf0d087251c67d5c934eb0ef4a70d5c51a00ee54f73e1e08903425",
    exp = "f35d4f200a780822124a0b081179e3d4a0d35510ab6e959e2c",
    mod = "8e99ae1be2d241aeeb84195f9b108f9cf349d985159faa81e4481dfa13d53823",
    result = "72dcd8f95d33f62a754cf474d81b6d956f6679ebc5728a1ef6933847d8770e26",
  },
  {
    base = "25ae403fe777a8a29bdd6a5789cc8bbaab9d2464af1aacb53ae32135898e6bfa",
    exp = "80b8f4c2e5ddf71127f4eb3aa7a10564fce9969b05172e80ba",
    mod = "9304db81ec231dd86cdebb4eda07e4970efba2ff86aa0709e9a1dcde6d0d33c5",
    result = "13449129cb254007fe2810d95a9b437feebc78a31c1e2fd5073ec2ef6b4df5e6",
  },
  {
    base = "69bb23c104796692e0b335cace9437938c7f88608b5b34eac5ee3bb98f7ffe43",
    exp = "29dd6ffbfa8abc5492e855efc01b31186cb4b55dc01dcb6cf0",
    mod = "b751b52d96495d031ff4ab3d7784abe057a84ec928c26106bb0412086eed0137",
    result = "a654ff028a94c301f72b0aefacd2c5c65499787ee00c5f15a0d022587ad07b99",
  },
}

--- Run comprehensive self-test with known-answer test vectors
---
--- Covers conversions, schoolbook arithmetic across limb boundaries, modular
--- arithmetic, and modular exponentiation up to full 3072-bit SRP operands.
--- It also asserts the two invariants this module is built around: that the
--- optimised Montgomery path agrees with the slow reference path, and that the
--- OpenSSL-accelerated path is bit-identical to the pure-Lua one.
---
--- @return boolean result True if all tests pass, false otherwise
local function selftest()
  print("Running bignum test vectors...")

  local from_hex = bignum.from_hex
  local to_hex = bignum.to_hex
  local from_number = bignum.from_number
  local equals = bignum.equals

  local N = from_hex(RFC5054_N_HEX)
  local G = from_number(5)
  local X = from_hex(VEC_X_HEX)
  local Y = from_hex(VEC_Y_HEX)
  local M = from_hex(VEC_M_HEX)

  -- Snapshot the OpenSSL state so the accelerator tests cannot leak.
  local saved_loaded = package.loaded["openssl"]
  local saved_preload = package.preload["openssl"]
  local saved_use = openssl_wrapper.enabled()

  -- The host's real binding, if any. Resolved now: install(nil) below makes require("openssl") fail.
  local real_loaded, real_binding = pcall(require, "openssl")
  if not real_loaded or type(real_binding) ~= "table" or type(real_binding.bn) ~= "table" then
    real_binding = nil
  end

  -- Limbs above which the stand-in's faults apply. Known-answer checks use at
  -- most 19 limbs, so a faulty stand-in still passes them.
  local WIDE = 32

  --- Stand-in lua-openssl binding over this module's own raw functions, so it
  --- tests routing and conversion, not OpenSSL. Like the real binding, it answers
  --- 0 for a zero divisor or modulus instead of raising.
  --- @param options table `spelling`: "powmod" or "mod_exp". `broken`: set of bn
  ---   function names that answer wrongly. `bad_remainder`: only divmod's
  ---   remainder is wrong. `small_only`: the exponentiation is wrong for any
  ---   multi-limb operand, which `Feature.BN`'s probe cannot see. Above `WIDE`
  ---   limbs, `mark_wide` adds one to each answer, `raise_wide` raises, and
  ---   `signed_hex` makes `tohex` prefix "-"
  --- @return table binding
  --- @return function calls `calls(name)` counts calls to one bn function; with no
  ---   name, the exponentiation under either spelling
  local function make_binding(options)
    local counts = {}
    local function enter(name, ...)
      counts[name] = (counts[name] or 0) + 1
      if options.raise_wide then
        for _, operand in ipairs({ ... }) do
          if #operand.value > WIDE then
            error("stand-in raised on a wide operand")
          end
        end
      end
      return options.broken ~= nil and options.broken[name] == true
    end
    local function handle(value)
      if options.mark_wide and #value > WIDE then
        return { value = add_raw(value, { 1 }) }
      end
      return { value = value }
    end
    local wrong = handle(from_number(1))
    local bnlib = {}
    bnlib.text = function(raw)
      enter("text")
      -- Matches lua-openssl's bn.text: big-endian bytes in.
      return { value = bignum.from_bytes(raw) }
    end
    bnlib.tohex = function(h)
      local hex = string_upper(to_hex(h.value))
      if options.signed_hex and #h.value > WIDE then
        return "-" .. hex
      end
      return hex
    end
    bnlib[options.spelling or "powmod"] = function(base, exp, modulus)
      if enter("powmod", base, exp, modulus) then
        return wrong
      end
      if options.small_only and (#base.value > 1 or #exp.value > 1 or #modulus.value > 1) then
        return wrong
      end
      if #modulus.value == 0 then
        return handle({})
      end
      return handle(mod_exp_reference(base.value, exp.value, modulus.value))
    end
    bnlib.mul = function(a, b)
      if enter("mul", a, b) then
        return wrong
      end
      return handle(mul_raw(a.value, b.value))
    end
    bnlib.divmod = function(a, b)
      if enter("divmod", a, b) then
        return wrong, wrong
      end
      if #b.value == 0 then
        return handle({}), handle({})
      end
      local quotient, remainder = divmod_raw(a.value, b.value)
      if options.bad_remainder then
        return handle(quotient), wrong
      end
      return handle(quotient), handle(remainder)
    end
    bnlib.mod = function(a, m)
      if enter("mod", a, m) then
        return wrong
      end
      if #m.value == 0 then
        return handle({})
      end
      local _, remainder = divmod_raw(a.value, m.value)
      return handle(remainder)
    end
    bnlib.mulmod = function(a, b, m)
      if enter("mulmod", a, b, m) then
        return wrong
      end
      if #m.value == 0 then
        return handle({})
      end
      local _, remainder = divmod_raw(mul_raw(a.value, b.value), m.value)
      return handle(remainder)
    end
    local binding = {
      version = function()
        return "0.9.2"
      end,
      bn = bnlib,
    }
    return binding, function(name)
      return counts[name or "powmod"] or 0
    end
  end

  --- Wrap a binding to record each hex string `bn.tohex` returns, as proof a result came from it.
  --- @param binding table Real lua-openssl module
  --- @return table proxy
  --- @return table<string, boolean> emitted Lowercase hex, leading zeros stripped
  local function recording_proxy(binding)
    local emitted = {}
    local bnlib = setmetatable({
      tohex = function(handle)
        local hex = binding.bn.tohex(handle)
        if type(hex) == "string" then
          emitted[(hex:lower():gsub("^0+(.)", "%1"))] = true
        end
        return hex
      end,
    }, { __index = binding.bn })
    return setmetatable({ bn = bnlib }, { __index = binding }), emitted
  end

  --- @param x BigNum[]
  --- @param y BigNum[]
  --- @return boolean
  local function same_values(x, y)
    if #x ~= #y then
      return false
    end
    for i = 1, #x do
      if type(y[i]) ~= "table" or not equals(x[i], y[i]) then
        return false
      end
    end
    return true
  end

  --- Every routed operation at SRP size, zeros included; mod_add and mod_sub get
  --- unreduced operands so they reach `mod`. Entries are { op, value, direct }, where
  --- `direct` is false for a value derived from `op`'s answer rather than returned by it.
  --- @return table[] entries
  local function routed_workload()
    local B = from_hex(SRP_EXP_B_HEX)
    local RA, RB = from_hex(SRP_RESULT_A_HEX), from_hex(SRP_RESULT_B_HEX)
    local NB = mul_raw(N, B)
    local wide = add_raw(NB, from_number(12345))
    local q1, r1 = bignum.divmod(wide, N)
    local q2, r2 = bignum.divmod(NB, N)
    return {
      { "mul", bignum.mul(N, B), true },
      { "divmod", q1, true },
      { "divmod", r1, true },
      { "divmod", q2, true },
      { "divmod", r2, true },
      { "mod", bignum.mod(wide, add_raw(N, { 1 })), true },
      { "mod", bignum.mod(NB, B), true },
      { "mod", bignum.mod_add(wide, NB, N), true },
      { "mod", bignum.mod_sub(N, wide, N), false },
      { "mod_mul", bignum.mod_mul(RA, RB, N), true },
      { "mod_exp", bignum.mod_exp(RA, from_number(65537), N), true },
      { "mod_exp", bignum.mod_exp(bignum.zero(), from_number(65537), N), true },
    }
  end

  --- @param entries table[]
  --- @return BigNum[]
  local function values_of(entries)
    local out = {}
    for i, entry in ipairs(entries) do
      out[i] = entry[2]
    end
    return out
  end

  --- Install a stand-in binding (or force acceleration off) and re-probe.
  --- @param binding table|nil Stand-in module, or nil for the pure-Lua path
  local function install(binding)
    package.loaded["openssl"] = binding
    if binding == nil then
      -- Force require("openssl") to fail regardless of what this host has.
      -- Each selftest stubs the same loader independently, which the language
      -- server reads as redefining one field; that is the intent here.
      --- @diagnostic disable-next-line: duplicate-set-field
      package.preload["openssl"] = function()
        error("simulated absent binding")
      end
    else
      package.preload["openssl"] = nil
    end
    openssl_wrapper.use(binding ~= nil)
  end

  -- Make the whole run deterministic: the vectors below exercise pure Lua.
  install(nil)

  local tests = {
    -- ---------------------------------------------------------------- bytes
    {
      name = "from_bytes/to_bytes round-trip",
      test = function()
        local raw = bytes.from_hex(VEC_X_HEX)
        return bignum.to_bytes(from_hex(VEC_X_HEX)) == raw and to_hex(bignum.from_bytes(raw)) == VEC_X_HEX
      end,
    },
    {
      name = "from_bytes ignores leading zero bytes",
      test = function()
        return equals(bignum.from_bytes(bytes.from_hex("00000001ff")), from_number(511))
      end,
    },
    {
      name = "to_bytes pads on the left when length is given",
      test = function()
        return bignum.to_bytes(from_number(511), 4) == bytes.from_hex("000001ff")
      end,
    },
    {
      name = "to_bytes preserves leading zeros through a round-trip",
      test = function()
        local padded = bignum.to_bytes(from_hex("0001ff"), 8)
        return #padded == 8 and padded == bytes.from_hex("00000000000001ff")
      end,
    },
    {
      name = "to_bytes rejects a length that cannot hold the value",
      test = function()
        return pcall(bignum.to_bytes, X, 8) == false
      end,
    },
    {
      name = "to_bytes of a 3072-bit value is exactly 384 bytes",
      test = function()
        return #bignum.to_bytes(N) == 384 and #bignum.to_bytes(N, 384) == 384
      end,
    },
    {
      name = "zero round-trips through bytes",
      test = function()
        local zero = bignum.zero()
        return bignum.is_zero(zero)
          and bignum.to_bytes(zero) == ""
          and bignum.to_bytes(zero, 4) == bytes.from_hex("00000000")
          and bignum.is_zero(bignum.from_bytes(""))
          and bignum.is_zero(bignum.from_bytes(bytes.from_hex("0000")))
      end,
    },
    -- ------------------------------------------------------------------ hex
    {
      name = "from_hex/to_hex round-trip on a 3072-bit value",
      test = function()
        return to_hex(N) == RFC5054_N_HEX and bignum.bit_length(N) == 3072
      end,
    },
    {
      name = "from_hex accepts uppercase and odd-length input",
      test = function()
        return equals(from_hex("ABCDEF"), from_hex("abcdef")) and to_hex(from_hex("fff")) == "fff"
      end,
    },
    {
      name = 'to_hex of zero is "0" and round-trips',
      test = function()
        return to_hex(bignum.zero()) == "0" and bignum.is_zero(from_hex("0")) and bignum.is_zero(from_hex(""))
      end,
    },
    {
      name = "from_hex rejects non-hex input",
      test = function()
        return pcall(from_hex, "12zz34") == false
      end,
    },
    -- --------------------------------------------------------------- number
    {
      name = "from_number across limb boundaries",
      test = function()
        return to_hex(from_number(0)) == "0"
          and to_hex(from_number(1)) == "1"
          and to_hex(from_number(16777215)) == "ffffff"
          and to_hex(from_number(16777216)) == "1000000"
          and to_hex(from_number(4294967296)) == "100000000"
      end,
    },
    {
      name = "from_number rejects negative, fractional and oversized input",
      test = function()
        return pcall(from_number, -1) == false
          and pcall(from_number, 1.5) == false
          and pcall(from_number, 2 ^ 60) == false
      end,
    },
    -- ----------------------------------------------------------- inspection
    {
      name = "bit_length and byte_length",
      test = function()
        return bignum.bit_length(bignum.zero()) == 0
          and bignum.byte_length(bignum.zero()) == 0
          and bignum.bit_length(X) == 256
          and bignum.byte_length(X) == 32
          and bignum.bit_length(Y) == 188
          and bignum.byte_length(Y) == 24
          and bignum.byte_length(N) == 384
      end,
    },
    {
      name = "compare and equals",
      test = function()
        return bignum.compare(X, Y) == 1
          and bignum.compare(Y, X) == -1
          and bignum.compare(X, X) == 0
          and equals(X, bignum.copy(X))
          and bignum.compare(from_number(16777216), from_number(16777215)) == 1
      end,
    },
    {
      name = "copy is independent of the original",
      test = function()
        local original = from_hex("0102030405060708090a")
        local duplicate = bignum.copy(original)
        duplicate[1] = 0
        return not equals(original, duplicate) and to_hex(original) == "102030405060708090a"
      end,
    },
    -- ----------------------------------------------------------- arithmetic
    {
      name = "add - unequal lengths (known answer)",
      test = function()
        return to_hex(bignum.add(X, Y)) == VEC_ADD_HEX and to_hex(bignum.add(Y, X)) == VEC_ADD_HEX
      end,
    },
    {
      name = "add - carry propagates across every limb",
      test = function()
        local all_ones = from_hex("ffffffffffffffffffffffffffffffffffffffffffffffff")
        return to_hex(bignum.add(all_ones, from_number(1))) == "1000000000000000000000000000000000000000000000000"
      end,
    },
    {
      name = "add - 3072-bit carry (N + 7)",
      test = function()
        return to_hex(bignum.add(N, from_number(7))) == SRP_BASE_OVER_N_HEX
      end,
    },
    {
      name = "add - identity with zero",
      test = function()
        return equals(bignum.add(X, bignum.zero()), X) and equals(bignum.add(bignum.zero(), X), X)
      end,
    },
    {
      name = "sub - unequal lengths (known answer)",
      test = function()
        return to_hex(bignum.sub(X, Y)) == VEC_SUB_HEX
      end,
    },
    {
      name = "sub - borrow propagates across every limb",
      test = function()
        local power = from_hex("1000000000000000000000000")
        local below = from_hex("ffffffffffffffffffffffff")
        return to_hex(bignum.sub(power, below)) == "1" and bignum.is_zero(bignum.sub(X, X))
      end,
    },
    {
      name = "sub - rejects a negative result",
      test = function()
        -- Equal widths too: only the final borrow can catch those.
        return pcall(bignum.sub, Y, X) == false
          and pcall(bignum.sub, from_number(5), from_number(7)) == false
          and pcall(bignum.sub, Y, bignum.add(Y, bignum.one())) == false
      end,
    },
    {
      name = "sub - rejects a wider subtrahend whose low limbs do not borrow",
      test = function()
        return pcall(bignum.sub, from_number(5), from_hex("1000000")) == false
          and pcall(bignum.sub, from_hex("ffffff"), from_hex("1000000")) == false
          and pcall(bignum.sub, X, bignum.add(X, from_hex("1" .. string_rep("0", 66)))) == false
          and to_hex(bignum.sub(from_hex("1000000"), from_hex("ffffff"))) == "1"
      end,
    },
    {
      name = "mul - unequal lengths (known answer)",
      test = function()
        return to_hex(bignum.mul(X, Y)) == VEC_MUL_HEX and to_hex(bignum.mul(Y, X)) == VEC_MUL_HEX
      end,
    },
    {
      name = "mul - all-ones squared exercises every carry",
      test = function()
        local all_ones = from_hex("ffffffffffffffffffffffffffffffffffffffffffffffff")
        local expected = "fffffffffffffffffffffffffffffffffffffffffffffffe"
          .. "000000000000000000000000000000000000000000000001"
        return to_hex(bignum.mul(all_ones, all_ones)) == expected
      end,
    },
    {
      name = "mul - power of two times its predecessor",
      test = function()
        local power = from_hex("1000000000000000000000000")
        local below = from_hex("ffffffffffffffffffffffff")
        return to_hex(bignum.mul(power, below)) == "ffffffffffffffffffffffff000000000000000000000000"
      end,
    },
    {
      name = "mul - zero and one",
      test = function()
        return bignum.is_zero(bignum.mul(X, bignum.zero()))
          and bignum.is_zero(bignum.mul(bignum.zero(), X))
          and equals(bignum.mul(X, bignum.one()), X)
      end,
    },
    {
      name = "divmod - multi-limb (known answer)",
      test = function()
        local quotient, remainder = bignum.divmod(X, Y)
        return to_hex(quotient) == VEC_QUO_HEX and to_hex(remainder) == VEC_REM_HEX
      end,
    },
    {
      name = "divmod - reconstructs the dividend",
      test = function()
        local quotient, remainder = bignum.divmod(X, Y)
        return equals(bignum.add(bignum.mul(quotient, Y), remainder), X) and bignum.compare(remainder, Y) < 0
      end,
    },
    {
      name = "divmod - single-limb divisor",
      test = function()
        local quotient, remainder = bignum.divmod(from_hex("1000000000000000000000001"), from_number(255))
        return equals(
          bignum.add(bignum.mul(quotient, from_number(255)), remainder),
          from_hex("1000000000000000000000001")
        ) and bignum.compare(remainder, from_number(255)) < 0
      end,
    },
    {
      name = "divmod - divisor larger than dividend",
      test = function()
        local quotient, remainder = bignum.divmod(Y, X)
        return bignum.is_zero(quotient) and equals(remainder, Y)
      end,
    },
    {
      name = "divmod - exact division leaves no remainder",
      test = function()
        local product = bignum.mul(X, Y)
        local quotient, remainder = bignum.divmod(product, Y)
        return equals(quotient, X) and bignum.is_zero(remainder)
      end,
    },
    {
      name = "divmod - rejects a zero divisor",
      test = function()
        return pcall(bignum.divmod, X, bignum.zero()) == false
      end,
    },
    {
      name = "mod - known answer",
      test = function()
        return to_hex(bignum.mod(X, M)) == VEC_MOD_X_HEX
      end,
    },
    -- ------------------------------------------------------ modular helpers
    {
      name = "mod_add - known answer",
      test = function()
        return to_hex(bignum.mod_add(X, Y, M)) == VEC_MOD_ADD_HEX
      end,
    },
    {
      name = "mod_sub - wraps to a non-negative residue when b > a",
      test = function()
        return to_hex(bignum.mod_sub(Y, X, M)) == VEC_MOD_SUB_HEX
      end,
    },
    {
      name = "mod_sub - plain difference when a >= b",
      test = function()
        return equals(bignum.mod_sub(X, Y, M), bignum.mod(bignum.sub(X, Y), M))
          and bignum.is_zero(bignum.mod_sub(X, X, M))
      end,
    },
    {
      name = "mod_mul - known answer",
      test = function()
        return to_hex(bignum.mod_mul(X, Y, M)) == VEC_MOD_MUL_HEX
      end,
    },
    -- ------------------------------------------------------------- mod_exp
    {
      name = "mod_exp - 4^13 mod 497 = 445",
      test = function()
        return equals(bignum.mod_exp(from_number(4), from_number(13), from_number(497)), from_number(445))
      end,
    },
    {
      name = "mod_exp - 2^10 mod 1000 = 24 (even modulus, reference path)",
      test = function()
        return equals(bignum.mod_exp(from_number(2), from_number(10), from_number(1000)), from_number(24))
          and equals(bignum.mod_exp(from_number(3), from_number(7), from_number(1000)), from_number(187))
      end,
    },
    {
      name = "mod_exp - exponent zero yields one",
      test = function()
        return equals(bignum.mod_exp(X, bignum.zero(), M), bignum.one())
          and equals(bignum.mod_exp(bignum.zero(), bignum.zero(), M), bignum.one())
      end,
    },
    {
      name = "mod_exp - base zero yields zero",
      test = function()
        return bignum.is_zero(bignum.mod_exp(bignum.zero(), from_number(5), from_number(7)))
          and bignum.is_zero(bignum.mod_exp(bignum.zero(), Y, M))
      end,
    },
    {
      name = "mod_exp - modulus one yields zero",
      test = function()
        return bignum.is_zero(bignum.mod_exp(X, Y, bignum.one()))
          and bignum.is_zero(bignum.mod_exp(from_number(123456789), bignum.zero(), bignum.one()))
      end,
    },
    {
      name = "mod_exp - rejects a zero modulus",
      test = function()
        return pcall(bignum.mod_exp, X, Y, bignum.zero()) == false
      end,
    },
    {
      name = "mod_exp - 192-bit modulus (known answer)",
      test = function()
        return to_hex(bignum.mod_exp(X, Y, M)) == VEC_MOD_EXP_HEX
      end,
    },
    {
      name = "mod_exp - RFC 5054 group 15: 5^a mod N, 256-bit exponent",
      test = function()
        return to_hex(bignum.mod_exp(G, from_hex(SRP_EXP_A_HEX), N)) == SRP_RESULT_A_HEX
      end,
    },
    {
      name = "mod_exp - RFC 5054 group 15: 5^b mod N, full 3072-bit exponent",
      test = function()
        return to_hex(bignum.mod_exp(G, from_hex(SRP_EXP_B_HEX), N)) == SRP_RESULT_B_HEX
      end,
    },
    {
      name = "mod_exp - RFC 5054 group 15: base greater than the modulus",
      test = function()
        local base = bignum.add(N, from_number(7))
        return to_hex(bignum.mod_exp(base, from_hex(SRP_EXP_A_HEX), N)) == SRP_RESULT_OVER_HEX
      end,
    },
    {
      name = "mod_exp - Montgomery path matches the slow reference path",
      test = function()
        for _, vector in ipairs(CROSS_CHECK_VECTORS) do
          local base, exp = from_hex(vector.base), from_hex(vector.exp)
          local modulus = from_hex(vector.mod)
          local fast = mod_exp_montgomery(base, exp, modulus)
          local slow = mod_exp_reference(base, exp, modulus)
          if to_hex(fast) ~= vector.result or to_hex(slow) ~= vector.result then
            return false
          end
        end
        return true
      end,
    },
    -- ------------------------------------------------------ acceleration
    {
      name = "accelerated mod_exp is identical to pure Lua (bn.powmod spelling)",
      test = function()
        install(nil)
        local pure = bignum.mod_exp(X, Y, M)
        local binding, calls = make_binding({ spelling = "powmod" })
        install(binding)
        local accelerated = bignum.mod_exp(X, Y, M)
        install(nil)
        -- calls() > 1 proves the routing fired: once to verify, once for real.
        return calls() > 1 and equals(accelerated, pure) and to_hex(accelerated) == VEC_MOD_EXP_HEX
      end,
    },
    {
      name = "accelerated mod_exp is identical to pure Lua (bn.mod_exp spelling)",
      test = function()
        install(nil)
        local pure = bignum.mod_exp(G, from_hex(SRP_EXP_A_HEX), N)
        local binding, calls = make_binding({ spelling = "mod_exp" })
        install(binding)
        local accelerated = bignum.mod_exp(G, from_hex(SRP_EXP_A_HEX), N)
        install(nil)
        return calls() > 1 and equals(accelerated, pure) and to_hex(accelerated) == SRP_RESULT_A_HEX
      end,
    },
    {
      name = "accelerated results are canonical limb tables, not handles",
      test = function()
        local binding = make_binding({})
        install(binding)
        local accelerated = bignum.mod_exp(X, Y, M)
        install(nil)
        -- Same canonical type either way, so a use_openssl() toggle mid-flight
        -- can never produce mixed-type operands.
        return type(accelerated) == "table" and equals(bignum.mod_mul(accelerated, bignum.one(), M), accelerated)
      end,
    },
    {
      name = "a binding that returns wrong answers is rejected, not trusted",
      test = function()
        local binding = make_binding({ broken = { powmod = true } })
        install(binding)
        local result = bignum.mod_exp(X, Y, M)
        install(nil)
        return to_hex(result) == VEC_MOD_EXP_HEX
      end,
    },
    {
      -- With raise_wide, every answer has to come back through the pure-Lua fallback.
      name = "every routed operation matches pure Lua at 3072 bits, zeros included, even when the binding raises",
      test = function()
        install(nil)
        local pure = values_of(routed_workload())
        for _, options in ipairs({ {}, { raise_wide = true } }) do
          local binding, calls = make_binding(options)
          install(binding)
          local accelerated = values_of(routed_workload())
          install(nil)
          if not same_values(pure, accelerated) then
            return false
          end
          -- At least two calls each: the known-answer check, then real work.
          for _, name in ipairs({ "mul", "divmod", "mod", "mulmod", "powmod" }) do
            if calls(name) < 2 then
              return false
            end
          end
        end
        return true
      end,
    },
    {
      name = "results come from the binding, not a silent fallback",
      test = function()
        install(nil)
        local pure = routed_workload()
        local binding = make_binding({ mark_wide = true })
        install(binding)
        local accelerated = routed_workload()
        install(nil)
        local marked = {}
        for i, entry in ipairs(pure) do
          local op, value, direct = entry[1], entry[2], entry[3]
          local expected = value
          if direct and #value > WIDE then
            expected = add_raw(value, { 1 })
            marked[op] = true
          end
          if not equals(accelerated[i][2], expected) then
            return false
          end
        end
        return marked.mul and marked.divmod and marked.mod and marked.mod_mul and marked.mod_exp or false
      end,
    },
    {
      -- Routed: the bn function runs twice (check, then work). Not routed: nothing is converted.
      name = "calls route where the work per converted limb reaches the threshold, and only there",
      test = function()
        local B = from_hex(SRP_EXP_B_HEX)
        local wide = mul_raw(N, B)
        local seven, byte = from_number(7), from_number(255)
        local a47, a48, b48 =
          from_hex(string_rep("ab", 141)), from_hex(string_rep("ab", 144)), from_hex(string_rep("cd", 144))
        --- @type table[]
        local shapes = {
          { false, bignum.mul, X, Y }, -- narrow operands
          { false, bignum.divmod, X, Y },
          { false, bignum.mod, X, M },
          { false, bignum.mul, a47, b48 }, -- 2256 limb products for 190 limbs converted: under 12
          { "mul", bignum.mul, a48, b48 }, -- 2304 for 192: exactly 12
          { false, bignum.mul, seven, wide }, -- a one-limb factor, either side
          { false, bignum.mul, wide, seven },
          { false, bignum.mul, bignum.zero(), bignum.zero() },
          { false, bignum.divmod, wide, byte }, -- a one-limb divisor
          { false, bignum.mod, wide, byte },
          { false, bignum.divmod, add_raw(N, B), N }, -- a quotient of a limb or two
          { false, bignum.mod, add_raw(N, B), N },
          { false, bignum.mod, N, B },
          { false, bignum.add, N, B }, -- linear at any width
          { false, bignum.sub, add_raw(N, B), B },
          { false, bignum.mod_add, N, B, N }, -- operands already reduced
          { false, bignum.mod_sub, B, N, N },
          { false, bignum.mod_mul, B, seven, N },
          { false, bignum.mod_mul, bignum.zero(), wide, N }, -- a zero factor
          { "mulmod", bignum.mod_mul, wide, from_number(3), N }, -- the reduction dominates
          { "mod", bignum.mod_add, wide, from_number(12345), N }, -- an unreduced operand
          { "mod", bignum.mod_sub, seven, wide, N },
        }
        for i, shape in ipairs(shapes) do
          local routed_to, call = shape[1], shape[2]
          install(nil)
          local pure = { call(shape[3], shape[4], shape[5]) }
          local binding, calls = make_binding({})
          install(binding)
          local got = { call(shape[3], shape[4], shape[5]) }
          install(nil)
          local routed = routed_to and calls(routed_to) == 2 or (not routed_to and calls("text") == 0)
          if not (routed and same_values(pure, got)) then
            error("shape " .. i .. " routed wrongly or changed its answer")
          end
        end
        return #a47 == 47 and #a48 == 48
      end,
    },
    {
      name = "a binding with one broken operation loses only that operation",
      test = function()
        local B = from_hex(SRP_EXP_B_HEX)
        local RA, RB = from_hex(SRP_RESULT_A_HEX), from_hex(SRP_RESULT_B_HEX)
        local wide = add_raw(mul_raw(N, B), from_number(12345))
        local N1 = add_raw(N, { 1 })
        local cases = {
          { broken = { mul = true }, bn = "mul", op = "mul" },
          { broken = { divmod = true }, bn = "divmod", op = "divmod" },
          { bad_remainder = true, bn = "divmod", op = "divmod" },
          { broken = { mod = true }, bn = "mod", op = "mod" },
          { broken = { mulmod = true }, bn = "mulmod", op = "mod_mul" },
        }
        local function run(op)
          if op == "mul" then
            return { bignum.mul(N, B) }
          elseif op == "divmod" then
            local quotient, remainder = bignum.divmod(wide, N)
            return { quotient, remainder }
          elseif op == "mod" then
            return { bignum.mod(wide, N1) }
          end
          return { bignum.mod_mul(RA, RB, N) }
        end
        for _, case in ipairs(cases) do
          install(nil)
          local pure = run(case.op)
          local binding, calls = make_binding(case)
          install(binding)
          local first, second = run(case.op), run(case.op)
          local verdicts = {}
          for _, op in ipairs({ "mul", "divmod", "mod", "mod_mul", "mod_exp" }) do
            verdicts[op] = bignum.is_accelerated(op)
          end
          install(nil)
          -- One call: the failed check is cached, not repeated per call.
          if not (same_values(pure, first) and same_values(pure, second) and calls(case.bn) == 1) then
            return false
          end
          for op, accelerated in pairs(verdicts) do
            if accelerated ~= (op ~= case.op) then
              return false
            end
          end
        end
        return true
      end,
    },
    {
      name = "a zero divisor or modulus raises the pure-Lua error with acceleration on",
      test = function()
        local wide = mul_raw(N, N)
        local zero = bignum.zero()
        local function failures()
          local messages = {}
          for i, call in ipairs({
            { bignum.divmod, wide, zero },
            { bignum.mod, wide, zero },
            { bignum.mod_mul, N, N, zero },
            { bignum.mod_add, N, N, zero },
            { bignum.mod_sub, N, wide, zero },
            { bignum.mod_exp, N, N, zero },
          }) do
            local ok, message = pcall(call[1], call[2], call[3], call[4])
            messages[i] = (not ok) and tostring(message) or false
          end
          return messages
        end
        install(nil)
        local expected = failures()
        local binding, calls = make_binding({})
        install(binding)
        local got = failures()
        install(nil)
        for i = 1, #expected do
          if expected[i] == false or got[i] ~= expected[i] then
            return false
          end
        end
        -- mod_mul(N, N, 0) passes the size rule, so require_nonzero is what kept it from mulmod.
        return calls("mulmod") == 1
      end,
    },
    {
      name = "signed hex from the binding is refused, not read as negative limbs",
      test = function()
        -- X * 16^112 is 30 limbs, wide enough against N to route. N times it is
        -- 944 hex digits, not a multiple of a limb's 6, so the "-" shares a chunk
        -- with digits and from_hex alone would read it as a negative limb.
        local wide_x = from_hex(VEC_X_HEX .. string_rep("0", 112))
        install(nil)
        local pure = bignum.mul(N, wide_x)
        local binding, calls = make_binding({ signed_hex = true })
        install(binding)
        local product = bignum.mul(N, wide_x)
        install(nil)
        return calls("mul") == 2 and equals(product, pure)
      end,
    },
    {
      name = (real_binding and "the host's lua-openssl agrees with pure Lua and is used wherever it is trusted")
        or "the host's lua-openssl agrees with pure Lua (skipped: no binding on this host)",
      test = function()
        if real_binding == nil then
          return true
        end
        install(nil)
        local pure = routed_workload()
        local proxy, emitted = recording_proxy(real_binding)
        install(proxy)
        -- Declining an operation is allowed here; each one trusted must return the binding's answer.
        local trusted = {}
        for _, op in ipairs({ "mul", "divmod", "mod", "mod_mul", "mod_exp" }) do
          trusted[op] = bignum.is_accelerated(op)
        end
        local accelerated = routed_workload()
        local exponentiated = trusted.mod_exp and bignum.mod_exp(G, from_hex(SRP_EXP_A_HEX), N) or nil
        install(nil)
        if not same_values(values_of(pure), values_of(accelerated)) then
          return false
        end
        for _, entry in ipairs(accelerated) do
          local op, value, direct = entry[1], entry[2], entry[3]
          if direct and trusted[op] and not bignum.is_zero(value) and not emitted[to_hex(value)] then
            return false
          end
        end
        return exponentiated == nil or (to_hex(exponentiated) == SRP_RESULT_A_HEX and emitted[SRP_RESULT_A_HEX] == true)
      end,
    },
    {
      name = "an absent binding falls back to pure Lua",
      test = function()
        install(nil)
        openssl_wrapper.use(true)
        local result = bignum.mod_exp(from_number(4), from_number(13), from_number(497))
        install(nil)
        return equals(result, from_number(445))
      end,
    },
    -- ----------------------------------------------- is_accelerated reporting
    -- A caller told only "false" cannot tell a host that will never accelerate
    -- from one where nobody called use_openssl(true), and the two need opposite
    -- responses. Each case below pins the phrase that distinguishes them.
    {
      -- The Control4 case: a working binding is present and nobody enabled it.
      name = "is_accelerated blames the flag when acceleration was never enabled, and the binding is untouched",
      test = function()
        local binding, calls = make_binding({})
        install(binding)
        openssl_wrapper.use(false)
        routed_workload()
        local accelerated, reason = bignum.is_accelerated()
        install(nil)
        return accelerated == false
          and type(reason) == "string"
          and reason:find("crypto.use_openssl(true)", 1, true) ~= nil
          and calls("text") == 0
      end,
    },
    {
      name = "is_accelerated blames the host when the binding is absent",
      test = function()
        install(nil)
        openssl_wrapper.use(true)
        local accelerated, reason = bignum.is_accelerated()
        install(nil)
        return accelerated == false
          and type(reason) == "string"
          and reason:find("not available", 1, true) ~= nil
          and reason:find("use_openssl", 1, true) == nil
      end,
    },
    {
      -- The binding computes 4^13 mod 497 correctly, so Feature.BN's probe
      -- passes; it is wrong on the multi-limb vector, so mod_exp will not use
      -- it. is_accelerated must agree with mod_exp, not with the feature gate.
      name = "is_accelerated blames the known-answer check for a single-limb-only binding",
      test = function()
        local binding = make_binding({ small_only = true })
        install(binding)
        local gated = openssl_wrapper.get(openssl_wrapper.Feature.BN) ~= nil
        local accelerated, reason = bignum.is_accelerated()
        local result = bignum.mod_exp(X, Y, M)
        install(nil)
        return gated == true
          and accelerated == false
          and type(reason) == "string"
          and reason:find("known-answer check", 1, true) ~= nil
          and to_hex(result) == VEC_MOD_EXP_HEX
      end,
    },
    {
      name = "is_accelerated is true with no reason for a trusted binding",
      test = function()
        local binding = make_binding({})
        install(binding)
        local accelerated, reason = bignum.is_accelerated()
        install(nil)
        return accelerated == true and reason == nil
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

  -- Restore the caller's state, acceleration choice included, so later tests in this process are unaffected.
  package.loaded["openssl"] = saved_loaded
  package.preload["openssl"] = saved_preload
  openssl_wrapper.use(saved_use)

  print(string_format("\nBignum result: %d/%d tests passed\n", passed, #tests))
  return passed == #tests
end

return selftest
