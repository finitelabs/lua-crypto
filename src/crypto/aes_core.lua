--- @module "crypto.aes_core"
--- The AES block cipher (FIPS-197), shared by the AES modes in this library.
---
--- Internal: `crypto.aes_gcm` builds on it, and the `crypto` aggregator does
--- not export it. It holds the pure-Lua key schedule and forward block
--- encryption; the AES modes here never use the inverse cipher.
--- @class crypto.aes_core
local aes_core = {}

local bit32 = require("bitn").bit32

-- Local references for performance
local bit32_raw_band = bit32.raw_band
local bit32_raw_bxor = bit32.raw_bxor
local bit32_raw_lshift = bit32.raw_lshift
local string_byte = string.byte
local string_char = string.char
local table_concat = table.concat

-- ============================================================================
-- AES CORE IMPLEMENTATION
-- ============================================================================

-- AES S-box (substitution box)
--- @type integer[]
local SBOX = {
  0x63,
  0x7c,
  0x77,
  0x7b,
  0xf2,
  0x6b,
  0x6f,
  0xc5,
  0x30,
  0x01,
  0x67,
  0x2b,
  0xfe,
  0xd7,
  0xab,
  0x76,
  0xca,
  0x82,
  0xc9,
  0x7d,
  0xfa,
  0x59,
  0x47,
  0xf0,
  0xad,
  0xd4,
  0xa2,
  0xaf,
  0x9c,
  0xa4,
  0x72,
  0xc0,
  0xb7,
  0xfd,
  0x93,
  0x26,
  0x36,
  0x3f,
  0xf7,
  0xcc,
  0x34,
  0xa5,
  0xe5,
  0xf1,
  0x71,
  0xd8,
  0x31,
  0x15,
  0x04,
  0xc7,
  0x23,
  0xc3,
  0x18,
  0x96,
  0x05,
  0x9a,
  0x07,
  0x12,
  0x80,
  0xe2,
  0xeb,
  0x27,
  0xb2,
  0x75,
  0x09,
  0x83,
  0x2c,
  0x1a,
  0x1b,
  0x6e,
  0x5a,
  0xa0,
  0x52,
  0x3b,
  0xd6,
  0xb3,
  0x29,
  0xe3,
  0x2f,
  0x84,
  0x53,
  0xd1,
  0x00,
  0xed,
  0x20,
  0xfc,
  0xb1,
  0x5b,
  0x6a,
  0xcb,
  0xbe,
  0x39,
  0x4a,
  0x4c,
  0x58,
  0xcf,
  0xd0,
  0xef,
  0xaa,
  0xfb,
  0x43,
  0x4d,
  0x33,
  0x85,
  0x45,
  0xf9,
  0x02,
  0x7f,
  0x50,
  0x3c,
  0x9f,
  0xa8,
  0x51,
  0xa3,
  0x40,
  0x8f,
  0x92,
  0x9d,
  0x38,
  0xf5,
  0xbc,
  0xb6,
  0xda,
  0x21,
  0x10,
  0xff,
  0xf3,
  0xd2,
  0xcd,
  0x0c,
  0x13,
  0xec,
  0x5f,
  0x97,
  0x44,
  0x17,
  0xc4,
  0xa7,
  0x7e,
  0x3d,
  0x64,
  0x5d,
  0x19,
  0x73,
  0x60,
  0x81,
  0x4f,
  0xdc,
  0x22,
  0x2a,
  0x90,
  0x88,
  0x46,
  0xee,
  0xb8,
  0x14,
  0xde,
  0x5e,
  0x0b,
  0xdb,
  0xe0,
  0x32,
  0x3a,
  0x0a,
  0x49,
  0x06,
  0x24,
  0x5c,
  0xc2,
  0xd3,
  0xac,
  0x62,
  0x91,
  0x95,
  0xe4,
  0x79,
  0xe7,
  0xc8,
  0x37,
  0x6d,
  0x8d,
  0xd5,
  0x4e,
  0xa9,
  0x6c,
  0x56,
  0xf4,
  0xea,
  0x65,
  0x7a,
  0xae,
  0x08,
  0xba,
  0x78,
  0x25,
  0x2e,
  0x1c,
  0xa6,
  0xb4,
  0xc6,
  0xe8,
  0xdd,
  0x74,
  0x1f,
  0x4b,
  0xbd,
  0x8b,
  0x8a,
  0x70,
  0x3e,
  0xb5,
  0x66,
  0x48,
  0x03,
  0xf6,
  0x0e,
  0x61,
  0x35,
  0x57,
  0xb9,
  0x86,
  0xc1,
  0x1d,
  0x9e,
  0xe1,
  0xf8,
  0x98,
  0x11,
  0x69,
  0xd9,
  0x8e,
  0x94,
  0x9b,
  0x1e,
  0x87,
  0xe9,
  0xce,
  0x55,
  0x28,
  0xdf,
  0x8c,
  0xa1,
  0x89,
  0x0d,
  0xbf,
  0xe6,
  0x42,
  0x68,
  0x41,
  0x99,
  0x2d,
  0x0f,
  0xb0,
  0x54,
  0xbb,
  0x16,
}

-- Round constants (Rcon) for key expansion
--- @type integer[]
local RCON = {
  0x01,
  0x02,
  0x04,
  0x08,
  0x10,
  0x20,
  0x40,
  0x80,
  0x1b,
  0x36,
}

--- @alias AESWord [integer, integer, integer, integer]
--- @alias AESState [AESWord, AESWord, AESWord, AESWord]

--- Initialize a 4-element AES word with zeros
--- @return AESWord word Initialized word
local function create_aes_word()
  --- @type AESWord
  return { 0, 0, 0, 0 }
end

--- Initialize a 4x4 AES state array with zeros
--- @return AESState state Initialized state
local function create_aes_state()
  --- @type AESState
  return {
    create_aes_word(),
    create_aes_word(),
    create_aes_word(),
    create_aes_word(),
  }
end

-- Pre-allocated state array for aes_encrypt_block()
local aes_state = create_aes_state()

-- Pre-allocated arrays for mix_columns()
local mix_a = create_aes_word()
local mix_b = create_aes_word()

--- XOR two 4-byte words
--- @param a AESWord 4-byte array
--- @param b AESWord 4-byte array
--- @return AESWord result 4-byte array
local function xor_words(a, b)
  return {
    bit32_raw_bxor(a[1], b[1]),
    bit32_raw_bxor(a[2], b[2]),
    bit32_raw_bxor(a[3], b[3]),
    bit32_raw_bxor(a[4], b[4]),
  }
end

--- Rotate word (circular left shift by 1 byte)
--- @param word AESWord 4-byte array
--- @return AESWord result Rotated 4-byte array
local function rot_word(word)
  return { word[2], word[3], word[4], word[1] }
end

--- Apply S-box substitution to a word
--- @param word AESWord 4-byte array
--- @return AESWord result Substituted 4-byte array
local function sub_word(word)
  local s_1 = assert(SBOX[word[1] + 1], "Invalid SBOX index " .. (word[1] + 1))
  local s_2 = assert(SBOX[word[2] + 1], "Invalid SBOX index " .. (word[2] + 1))
  local s_3 = assert(SBOX[word[3] + 1], "Invalid SBOX index " .. (word[3] + 1))
  local s_4 = assert(SBOX[word[4] + 1], "Invalid SBOX index " .. (word[4] + 1))
  return { s_1, s_2, s_3, s_4 }
end

--- AES key expansion
--- @param key string Encryption key (16, 24, or 32 bytes)
--- @return table expanded_key Array of round keys
--- @return integer nr Number of rounds
local function key_expansion(key)
  local key_len = #key
  local nr -- Number of rounds
  local nk -- Number of 32-bit words in key

  if key_len == 16 then
    nr = 10
    nk = 4
  elseif key_len == 24 then
    nr = 12
    nk = 6
  elseif key_len == 32 then
    nr = 14
    nk = 8
  else
    error("Invalid key length. Must be 16, 24, or 32 bytes")
  end

  -- Convert key to words
  --- @type AESState
  local w = {}
  for i = 1, nk do
    w[i] = {
      string_byte(key, (i - 1) * 4 + 1),
      string_byte(key, (i - 1) * 4 + 2),
      string_byte(key, (i - 1) * 4 + 3),
      string_byte(key, (i - 1) * 4 + 4),
    }
  end

  -- Expand key
  for i = nk + 1, 4 * (nr + 1) do
    local temp = w[i - 1]
    local idx = i - 1 -- 0-based index for modulo arithmetic
    if idx % nk == 0 then
      local t = assert(RCON[idx / nk], "Invalid RCON index " .. (idx / nk))
      temp = xor_words(sub_word(rot_word(temp)), { t, 0, 0, 0 })
    elseif nk > 6 and idx % nk == 4 then
      temp = sub_word(temp)
    end
    w[i] = xor_words(w[i - nk], temp)
  end

  return w, nr
end

--- MixColumns transformation
--- @param state AESState 4x4 state matrix
local function mix_columns(state)
  -- Reuse pre-allocated arrays
  local a = mix_a
  local b = mix_b
  for c = 1, 4 do
    for i = 1, 4 do
      a[i] = state[i][c]
      b[i] = bit32_raw_band(state[i][c], 0x80) ~= 0
          and bit32_raw_bxor(bit32_raw_band(bit32_raw_lshift(state[i][c], 1), 0xFF), 0x1B)
        or bit32_raw_band(bit32_raw_lshift(state[i][c], 1), 0xFF)
    end

    state[1][c] = bit32_raw_bxor(bit32_raw_bxor(bit32_raw_bxor(b[1], a[2]), bit32_raw_bxor(b[2], a[3])), a[4])
    state[2][c] = bit32_raw_bxor(bit32_raw_bxor(bit32_raw_bxor(a[1], b[2]), bit32_raw_bxor(a[3], b[3])), a[4])
    state[3][c] = bit32_raw_bxor(bit32_raw_bxor(bit32_raw_bxor(a[1], a[2]), bit32_raw_bxor(b[3], a[4])), b[4])
    state[4][c] = bit32_raw_bxor(bit32_raw_bxor(bit32_raw_bxor(a[1], b[1]), bit32_raw_bxor(a[2], a[3])), b[4])
  end
end

--- SubBytes transformation
--- @param state AESState 4x4 state matrix
local function sub_bytes(state)
  for i = 1, 4 do
    for j = 1, 4 do
      local s_index = state[i][j] + 1
      state[i][j] = assert(SBOX[s_index], "Invalid SBOX index " .. s_index)
    end
  end
end

--- ShiftRows transformation
--- @param state AESState 4x4 state matrix
local function shift_rows(state)
  -- Row 1: no shift
  -- Row 2: shift left by 1
  local temp = state[2][1]
  state[2][1] = state[2][2]
  state[2][2] = state[2][3]
  state[2][3] = state[2][4]
  state[2][4] = temp

  -- Row 3: shift left by 2
  temp = state[3][1]
  state[3][1] = state[3][3]
  state[3][3] = temp
  temp = state[3][2]
  state[3][2] = state[3][4]
  state[3][4] = temp

  -- Row 4: shift left by 3 (or right by 1)
  temp = state[4][4]
  state[4][4] = state[4][3]
  state[4][3] = state[4][2]
  state[4][2] = state[4][1]
  state[4][1] = temp
end

--- AddRoundKey transformation
--- @param state AESState 4x4 state matrix
--- @param round_key table Round key words
--- @param round integer Round number
local function add_round_key(state, round_key, round)
  for c = 1, 4 do
    local key_word = round_key[round * 4 + c]
    for r = 1, 4 do
      state[r][c] = bit32_raw_bxor(state[r][c], key_word[r])
    end
  end
end

--- AES block encryption
--- @param input string 16-byte plaintext block
--- @param expanded_key table Expanded key
--- @param nr integer Number of rounds
--- @return string ciphertext 16-byte encrypted block
local function aes_encrypt_block(input, expanded_key, nr)
  -- Reuse pre-allocated state array
  local state = aes_state
  for i = 1, 4 do
    for j = 1, 4 do
      state[i][j] = string_byte(input, (j - 1) * 4 + i)
    end
  end

  -- Initial round
  add_round_key(state, expanded_key, 0)

  -- Main rounds
  for round = 1, nr - 1 do
    sub_bytes(state)
    shift_rows(state)
    mix_columns(state)
    add_round_key(state, expanded_key, round)
  end

  -- Final round (no MixColumns)
  sub_bytes(state)
  shift_rows(state)
  add_round_key(state, expanded_key, nr)

  -- Convert state to output (optimized with table)
  local output_bytes = {}
  local idx = 1
  for j = 1, 4 do
    for i = 1, 4 do
      output_bytes[idx] = string_char(state[i][j])
      idx = idx + 1
    end
  end

  return table_concat(output_bytes)
end

-- ============================================================================
-- PUBLIC INTERFACE
-- ============================================================================

aes_core.expand_key = key_expansion
aes_core.encrypt_block = aes_encrypt_block

return aes_core
