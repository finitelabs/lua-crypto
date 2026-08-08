#!/usr/bin/env python3
"""Generate SRP-6a known-answer vectors for crypto.srp.

RFC 5054 appendix B publishes vectors for SHA-1 with the 1024-bit group, which
validates the algorithm but not the parameter set HAP uses (RFC 5054 group 15,
3072-bit, SHA-512). This script produces vectors for that parameter set using
`srptools`, which is the library pyatv itself drives for HAP Pair-Setup, so the
vectors encode the convention that actually interoperates with an Apple TV
rather than a from-scratch reading of the RFC.

Everything is deterministic: the salt and both private exponents are fixed
literals, so re-running this reproduces the committed vectors byte for byte.

Usage:
    pip install srptools
    python3 tools/generate_srp_vectors.py            # emit the Lua table
    python3 tools/generate_srp_vectors.py --check    # verify internal consistency only

Paste the output into the `srp_vectors` table in src/crypto/srp.lua.
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import sys

from srptools import SRPClientSession, SRPContext, SRPServerSession, constants
from srptools.utils import int_from_hex, int_to_bytes

# The HAP parameter set. `SRPContext` takes hex strings.
PRIME = constants.PRIME_3072
GENERATOR = constants.PRIME_3072_GEN
HASH_FUNC = hashlib.sha512
USERNAME = "Pair-Setup"

N = int_from_hex(PRIME)
N_BYTES = len(int_to_bytes(N))  # 384


def h(*chunks: bytes) -> bytes:
    return HASH_FUNC(b"".join(chunks)).digest()


def pad(value: int) -> bytes:
    """PAD(x): left-pad to the byte length of N, as RFC 5054 specifies."""
    return int_to_bytes(value).rjust(N_BYTES, b"\x00")


def minimal(value: int) -> bytes:
    """srptools' default int encoding: big-endian, leading zero bytes stripped.

    This is NOT PAD(). srptools applies PAD() only to `u`'s inputs and to `g`
    inside `k`; everywhere else -- notably the salt, A and B inside M1 -- an int
    is rendered by `'%x' % val` and zero-padded only to an even hex length. A
    value whose top byte is zero is therefore one byte shorter than PAD() would
    make it. See the `leading_zero_salt` case below.
    """
    return int_to_bytes(value)


# Deterministic inputs. `a` is 32 bytes because pyatv seeds the client private
# exponent with the hexlified Ed25519 auth key, i.e. a 256-bit value.
CASES = [
    {
        "name": "HAP Pair-Setup, 8-digit PIN",
        "password": "123-45-678",
        "salt_hex": "beb25379d1a8581eb5a727673a2441ee",
        "a_hex": "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
        "b_hex": "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
    },
    {
        "name": "HAP Pair-Setup, 4-digit PIN",
        "password": "3939",
        "salt_hex": "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
        "a_hex": "1d1e2f3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6",
        "b_hex": "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0",
    },
    {
        # Salt whose leading byte is zero. Under PAD() this is 16 bytes; under
        # srptools' minimal encoding it is 15, and x = H(s | ...) changes
        # accordingly. This case exists specifically to pin which convention
        # crypto.srp implements, because getting it wrong is a ~1-in-256
        # intermittent pairing failure rather than an obvious break.
        "name": "leading-zero salt (pins the minimal-length encoding)",
        "password": "123-45-678",
        "salt_hex": "00b25379d1a8581eb5a727673a2441ee",
        "a_hex": "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
        "b_hex": "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
    },
]


def build(case: dict) -> dict:
    # The salt is BYTES, not an int, and that distinction is the whole point of
    # the third case. pyatv passes binascii.hexlify(atv_salt), and srptools'
    # init_base() unhexlifies straight to bytes, so a leading zero byte survives.
    # Routing it through int -> hex -> bytes here would silently drop that byte
    # and the vector would quietly stop testing what it claims to test.
    salt = binascii.unhexlify(case["salt_hex"])
    a = int_from_hex(case["a_hex"])
    b = int_from_hex(case["b_hex"])

    context = SRPContext(
        USERNAME,
        case["password"],
        prime=PRIME,
        generator=GENERATOR,
        hash_func=HASH_FUNC,
    )

    # Server side: derive the verifier from *this* salt, not the random one
    # get_user_data_triplet() would invent, then run a session with a fixed
    # private exponent so B is reproducible.
    x_for_verifier = context.get_common_password_hash(salt)  # salt is bytes
    password_verifier = "%x" % context.get_common_password_verifier(x_for_verifier)
    server = SRPServerSession(context, password_verifier, private=case["b_hex"])
    assert int_from_hex(server.private) == b

    client = SRPClientSession(context, private=case["a_hex"])
    client.process(server.public, case["salt_hex"])
    server.process(client.public, case["salt_hex"])

    # Both sides must agree, or the vector is worthless.
    assert client.key == server.key, "session keys diverged"
    # In srptools both roles expose key_proof = M1 and key_proof_hash = M2, so
    # the cross-checks compare like with like.
    assert server.verify_proof(client.key_proof), "server rejected M1"
    assert client.verify_proof(server.key_proof_hash), "client rejected M2"
    assert client.key_proof == server.key_proof, "M1 diverged between roles"
    assert client.key_proof_hash == server.key_proof_hash, "M2 diverged between roles"

    A = int_from_hex(client.public)
    B = int_from_hex(server.public)
    x = context.get_common_password_hash(salt)
    u = context.get_common_secret(B, A)
    S = context.get_client_premaster_secret(x, B, a, u)
    k = context._mult  # noqa: SLF001 - the library exposes no accessor

    # Independently recompute K, M1 and M2 from the primitives rather than
    # trusting the library's own bookkeeping, so a vector cannot be self-consistent
    # and wrong at the same time.
    K = h(minimal(S))
    assert binascii.unhexlify(client.key) == K, "K mismatch"
    M1 = h(
        bytes(p ^ q for p, q in zip(h(minimal(N)), h(minimal(context._gen)))),  # noqa: SLF001
        h(USERNAME.encode()),
        salt,
        minimal(A),
        minimal(B),
        K,
    )
    assert binascii.unhexlify(client.key_proof) == M1, "M1 mismatch"
    M2 = h(minimal(A), M1, K)
    assert binascii.unhexlify(server.key_proof_hash) == M2, "M2 mismatch"

    return {
        "name": case["name"],
        "password": case["password"],
        "salt": case["salt_hex"],
        "a": case["a_hex"],
        "b": case["b_hex"],
        "k": "%x" % k,
        "x": "%x" % x,
        "v": "%x" % int_from_hex(password_verifier),
        "A": "%0*x" % (N_BYTES * 2, A),
        "B": "%0*x" % (N_BYTES * 2, B),
        "u": "%x" % u,
        "S": "%0*x" % (N_BYTES * 2, S),
        "K": binascii.hexlify(K).decode(),
        "M1": binascii.hexlify(M1).decode(),
        "M2": binascii.hexlify(M2).decode(),
    }


def lua_string(value: str, indent: str) -> str:
    """Emit a long hex literal as concatenated 64-character chunks."""
    chunks = [value[i : i + 64] for i in range(0, len(value), 64)]
    if len(chunks) == 1:
        return '"%s"' % chunks[0]
    body = ('\n%s  .. ' % indent).join('"%s"' % c for c in chunks)
    return body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="verify only, emit nothing")
    args = parser.parse_args()

    results = [build(case) for case in CASES]
    if args.check:
        print("all %d vectors internally consistent" % len(results), file=sys.stderr)
        return 0

    print("-- Generated by tools/generate_srp_vectors.py -- do not edit by hand.")
    print("-- Source of truth: srptools, the library pyatv drives for HAP Pair-Setup.")
    print("local srp_vectors = {")
    for r in results:
        print("  {")
        print('    name = "%s",' % r["name"])
        print('    password = "%s",' % r["password"])
        for field in ("salt", "a", "b", "k", "x", "v", "A", "B", "u", "S", "K", "M1", "M2"):
            print("    %s = %s," % (field, lua_string(r[field], "    ")))
        print("  },")
    print("}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
