local spake2plus = require("crypto.spake2plus")
local p256 = require("crypto.p256")
local utils = require("crypto.utils")
local bytes = utils.bytes
local table_concat = table.concat

local benchmark_op = require("benchmark").benchmark_op

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

--- Run performance benchmarks for SPAKE2+, both roles.
local function benchmark()
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

return benchmark
