--- @module "crypto.poly1305"
--- Poly1305 Message Authentication Code (MAC) Implementation for portability.
--- @class crypto.poly1305
local poly1305 = {}

local bit32 = require("bitn").bit32

-- Local references for performance
local bit32_raw_band = bit32.raw_band
local bit32_raw_lshift = bit32.raw_lshift
local floor = math.floor
local string_byte = string.byte
local string_char = string.char
local table_concat = table.concat

-- Type definitions for better type checking

--- 17-element limb array for 130-bit + overflow
--- @alias Limb17Array [integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer]

--- 33-element array for multiplication products
--- @alias Limb33Array [integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer]

--- 16-element key array
--- @alias KeyArray [integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer]

--- Helper function to process modular reduction for higher-order terms
---
--- Reduces coefficients of 2^k where k >= 130 using the identity:
--- 2^130 ≡ 5 (mod 2^130 - 5)
---
--- @param prod Limb33Array Product array to reduce
--- @param start_pos integer Starting position to reduce from
--- @param end_pos integer Ending position to reduce to
local function reduce_high_order_terms(prod, start_pos, end_pos)
  for i = start_pos, end_pos, -1 do
    if prod[i] > 0 then
      local bit_pos = 8 * (i - 1)
      local excess_bits = bit_pos - 130
      local reduction_multiplier = 5

      -- Calculate target byte position for the reduction
      local target_byte = 1 + floor(excess_bits / 8)
      local bit_offset = excess_bits % 8

      if bit_offset > 0 then
        reduction_multiplier = bit32_raw_lshift(reduction_multiplier, bit_offset)
      end

      -- Add reduced value to target position
      if target_byte <= 17 then
        prod[target_byte] = prod[target_byte] + prod[i] * reduction_multiplier
      end
      prod[i] = 0
    end
  end
end

--- Helper function to propagate carries in limb array
---
--- Normalizes a limb array by propagating carries from lower to higher positions.
--- Each limb is reduced modulo 256 (8-bit) with carries propagated forward.
---
--- @param h Limb17Array|Limb33Array Limb array to normalize (modified in place)
--- @return integer carry Final carry value
local function propagate_carries(h)
  local carry = 0
  for i = 1, 17 do
    assert(h[i] ~= nil, "Limb array must have at least 17 non-nil elements")
    carry = carry + h[i]
    h[i] = carry % 256
    carry = floor(carry / 256)
  end
  return carry
end

--- Helper function to handle final carry overflow
---
--- When carry propagation results in overflow beyond position 17,
--- this function applies the modular reduction: 2^136 ≡ 320 (mod 2^130 - 5)
---
--- @param h Limb17Array Limb array (modified in place)
--- @param carry integer Initial carry to process
local function handle_final_carry(h, carry)
  while carry > 0 do
    -- 2^136 = 2^6 * 2^130 ≡ 64 * 5 = 320 (mod 2^130 - 5)
    h[1] = h[1] + carry * 320

    carry = propagate_carries(h)
  end
end

--- Helper function to reduce limb 17 to valid range
---
--- Position 17 can only hold 2 bits (values 0-3) since we're working modulo 2^130.
--- Values >= 4 represent overflow that must be reduced.
---
--- @param h Limb17Array Limb array (modified in place)
local function reduce_position_17(h)
  while h[17] >= 4 do
    local high_bits = floor(h[17] / 4)
    h[17] = h[17] % 4

    -- high_bits represents coefficient of 2^130, so multiply by 5
    h[1] = h[1] + high_bits * 5

    local carry = propagate_carries(h)
    handle_final_carry(h, carry)
  end
end

--- Initialize a 17-element limb array with zeros
--- @return Limb17Array array Initialized array
local function create_limb17_array()
  local arr = {}
  for i = 1, 17 do
    arr[i] = 0
  end
  --- @cast arr Limb17Array
  return arr
end

--- Initialize a 33-element product array with zeros
--- @return Limb33Array array Initialized array
local function create_limb33_array()
  local arr = {}
  for i = 1, 33 do
    arr[i] = 0
  end
  --- @cast arr Limb33Array
  return arr
end

-- Pre-allocated arrays for authenticate() hot loop
local auth_c = create_limb17_array() -- Message block array (17 elements)
local auth_prod = create_limb33_array() -- Product array (33 elements)
local auth_g = create_limb17_array() -- Final reduction array (17 elements)

--- Initialize a 16-element key array
--- @param source integer[] Source array to copy from
--- @param offset integer Starting offset in source array
--- @return KeyArray array Initialized key array
local function create_key_array(source, offset)
  local arr = {}
  for i = 1, 16 do
    arr[i] = source[offset + i - 1]
  end
  --- @cast arr KeyArray
  return arr
end

--- Compute Poly1305 MAC for given key and message
---
--- This function implements the complete Poly1305 algorithm:
--- 1. Key setup with RFC 7539 clamping
--- 2. Message processing in 16-byte blocks with padding
--- 3. Modular arithmetic over the field 2^130 - 5
--- 4. Final reduction and output formatting
---
--- @param key string 32-byte key (r || s)
--- @param msg string Message to authenticate (any length)
--- @return string mac 16-byte authentication tag
--- @error Throws assertion error if key is not exactly 32 bytes
function poly1305.authenticate(key, msg)
  assert(#key == 32, "Key must be exactly 32 bytes")

  -- Convert key to byte array for easier manipulation
  --- @type integer[]
  local key_bytes = {}
  for i = 1, #key do
    key_bytes[i] = string_byte(key, i)
  end

  -- Extract and clamp r (first 16 bytes) per RFC 7539
  local r = create_key_array(key_bytes, 1)

  -- Apply RFC 7539 clamping to ensure r has specific bit patterns
  -- This prevents certain classes of attacks and ensures key validity
  r[4] = bit32_raw_band(r[4], 15) -- Clear top 4 bits of 4th byte
  r[5] = bit32_raw_band(r[5], 252) -- Clear bottom 2 bits of 5th byte
  r[8] = bit32_raw_band(r[8], 15) -- Clear top 4 bits of 8th byte
  r[9] = bit32_raw_band(r[9], 252) -- Clear bottom 2 bits of 9th byte
  r[12] = bit32_raw_band(r[12], 15) -- Clear top 4 bits of 12th byte
  r[13] = bit32_raw_band(r[13], 252) -- Clear bottom 2 bits of 13th byte
  r[16] = bit32_raw_band(r[16], 15) -- Clear top 4 bits of 16th byte

  -- Extract s (second 16 bytes) - used for final addition
  local s = create_key_array(key_bytes, 17)

  -- Initialize accumulator h as 17-byte array (130-bit + 6 extra bits)
  local h = create_limb17_array()

  local msglen = #msg
  local offset = 1

  -- Reuse pre-allocated arrays for hot loop
  local c = auth_c
  local prod = auth_prod

  -- Process message in 16-byte blocks
  while msglen >= 16 do
    -- Load current 16-byte block (reset and fill)
    for i = 1, 16 do
      c[i] = string_byte(msg, offset + i - 1)
    end
    c[17] = 1 -- Add high bit (represents 2^128 for full blocks)

    -- Add message block to accumulator: h = h + c
    local carry = 0
    for i = 1, 17 do
      carry = carry + h[i] + c[i]
      h[i] = carry % 256
      carry = floor(carry / 256)
    end

    -- Multiply by r: h = (h * r) mod (2^130 - 5)

    -- Step 1: Compute full precision product h * r (reset prod first)
    for i = 1, 33 do
      prod[i] = 0
    end

    for i = 1, 17 do
      for j = 1, 16 do
        prod[i + j - 1] = prod[i + j - 1] + h[i] * r[j]
      end
    end

    -- Step 2: Reduce high-order terms (positions 18-33)
    reduce_high_order_terms(prod, 33, 18)

    -- Step 3: Propagate carries and normalize
    carry = propagate_carries(prod)
    for i = 1, 17 do
      h[i] = prod[i]
    end

    -- Step 4: Handle overflow carry
    handle_final_carry(h, carry)

    -- Step 5: Reduce position 17 to valid range
    reduce_position_17(h)

    offset = offset + 16
    msglen = msglen - 16
  end

  -- Process final partial block (if any)
  if msglen > 0 then
    -- Reset c array for partial block
    for i = 1, 17 do
      c[i] = 0
    end

    -- Load partial block
    for i = 1, msglen do
      c[i] = string_byte(msg, offset + i - 1)
    end
    c[msglen + 1] = 1 -- Add padding bit at end of message

    -- Same operations as full blocks
    local carry = 0
    for i = 1, 17 do
      carry = carry + h[i] + c[i]
      h[i] = carry % 256
      carry = floor(carry / 256)
    end

    -- Multiply by r (reset prod first)
    for i = 1, 33 do
      prod[i] = 0
    end

    for i = 1, 17 do
      for j = 1, 16 do
        prod[i + j - 1] = prod[i + j - 1] + h[i] * r[j]
      end
    end

    reduce_high_order_terms(prod, 33, 18)

    carry = propagate_carries(prod)
    for i = 1, 17 do
      h[i] = prod[i]
    end

    handle_final_carry(h, carry)
    reduce_position_17(h)
  end

  -- Final reduction: conditionally subtract (2^130 - 5) if h >= 2^130 - 5
  -- This ensures the result is in canonical form

  -- Reuse pre-allocated g array
  local g = auth_g
  for i = 1, 17 do
    g[i] = h[i]
  end

  -- Test reduction by computing h + 5
  g[1] = g[1] + 5
  local carry = floor(g[1] / 256)
  g[1] = g[1] % 256

  for i = 2, 17 do
    if carry == 0 then
      break
    end
    carry = carry + g[i]
    g[i] = carry % 256
    carry = floor(carry / 256)
  end

  -- Use mask-based selection for constant-time operation
  -- If g[17] >= 4, then h + 5 overflowed the 130-bit boundary,
  -- meaning h >= 2^130 - 5, so we use the reduced value g
  local use_g = (g[17] >= 4) and 1 or 0
  for i = 1, 17 do
    h[i] = (h[i] * (1 - use_g)) + (g[i] * use_g)
  end

  -- Add s and create final 16-byte result (optimized with table)
  local result_bytes = {}
  carry = 0
  for i = 1, 16 do
    local sum = h[i] + s[i] + carry
    result_bytes[i] = string_char(sum % 256)
    carry = floor(sum / 256)
  end

  return table_concat(result_bytes)
end

return poly1305
