--- Benchmarks for crypto.bignum: `make bench` runs them, and so does the with-tests build's benchmark().

local bignum = require("crypto.bignum")

local benchmark_op = require("benchmark").benchmark_op

--- RFC 5054 Appendix A / RFC 3526 group 15: the 3072-bit safe prime N.
--- Its generator is g = 5.
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

--- Run performance benchmarks
---
--- The headline number is a 3072-bit modular exponentiation with a full-size
--- 3072-bit exponent: that is the SRP-6a server operation, and it decides
--- whether the pure-Lua path is shippable on an embedded controller. Iteration
--- counts are small because a single such operation takes seconds.
local function benchmark()
  local N = bignum.from_hex(RFC5054_N_HEX)
  local G = bignum.from_number(5)
  local exp_short = bignum.from_hex(SRP_EXP_A_HEX)
  local exp_full = bignum.from_hex(SRP_EXP_B_HEX)
  local wide = bignum.mul(N, N)

  print("Modular exponentiation (RFC 5054 group 15, 3072-bit N):")
  benchmark_op("mod_exp 3072-bit exponent", function()
    bignum.mod_exp(G, exp_full, N)
  end, 2)

  benchmark_op("mod_exp 256-bit exponent", function()
    bignum.mod_exp(G, exp_short, N)
  end, 5)

  print("\nCore arithmetic:")
  benchmark_op("mul 3072 x 3072 bits", function()
    bignum.mul(N, N)
  end, 200)

  benchmark_op("divmod 6144 / 3072 bits", function()
    bignum.divmod(wide, N)
  end, 100)

  benchmark_op("mod_mul 3072-bit", function()
    bignum.mod_mul(N, N, N)
  end, 100)
end

return benchmark
