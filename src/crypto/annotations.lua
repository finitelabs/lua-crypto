--- Shared LuaCATS type aliases.
---
--- This file contains no code and is never `require`d. It exists so that types
--- used by more than one module have exactly one definition: the Lua language
--- server resolves `@alias` workspace-wide, so a name defined in two modules is
--- a `duplicate-doc-alias` warning even when both definitions agree, while a
--- name used but defined nowhere is `undefined-doc-name` at every use site.
---
--- Because nothing requires it, `amalg` (which traces an actual run of
--- `crypto.init`) does not bundle it and the shipped builds are unchanged.
---
--- Do not add runtime code here. Types used by a single module stay in that
--- module, next to what they describe.

-- ----------------------------------------------------------------------------
-- Curve25519 field arithmetic
-- ----------------------------------------------------------------------------
-- x25519 and ed25519 compute over the same prime field p = 2^255 - 19 with the
-- same 16-limb representation, so these describe one type used by two modules
-- rather than two similar ones.

--- @alias FieldElement integer[] 16-element array (indices 1-16) representing a field element
--- @alias ProductArray integer[] 31-element array (indices 1-31) for multiplication products

-- ----------------------------------------------------------------------------
-- 64-bit values on 32-bit-safe runtimes
-- ----------------------------------------------------------------------------
-- Lua 5.1/5.2 have no 64-bit integers and 5.3+ `//` semantics differ, so the
-- 64-bit primitives (SHA-512, BLAKE2b) carry 64-bit quantities as a pair of
-- 32-bit halves. Used by `utils/bytes`, `sha512` and `blake2`.

--- @alias Int64HighLow { [1]: integer, [2]: integer } 64-bit value as {high, low} 32-bit halves
