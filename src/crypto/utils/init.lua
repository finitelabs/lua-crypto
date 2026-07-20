--- @module "crypto.utils"
--- Common utility functions for the Noise Protocol Framework
--- @class crypto.utils
local utils = {
  --- @type crypto.utils.bytes
  bytes = require("crypto.utils.bytes"),
  --- @type crypto.utils.benchmark
  benchmark = require("crypto.utils.benchmark"),
}

return utils
