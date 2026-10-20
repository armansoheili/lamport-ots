"""Lamport one-time signatures over SHA-256. Zero dependencies.

A Lamport keypair binds a message to exactly ONE signature. Each secret
revealed in a signature can never be reused: signing a second message
leaks more secrets and lets an attacker forge signatures.

Scheme (n = 256 bits):
  sk = n pairs of random 32-byte secrets:  sk[i][0], sk[i][1]
  pk = n pairs of SHA-256 digests:          pk[i][b] = SHA256(sk[i][b])
  sign(sk, msg): for bit b_i of SHA256(msg), reveal sk[i][b_i]
  verify(pk, msg, sig): check SHA256(sig[i]) == pk[i][b_i] for every i

Example (run with: python3 lamport.py --demo)::

    >>> import random
    >>> random.seed(7)
    >>> sk, pk = gen_keypair()
    >>> sig = sign(sk, b"pay alice 0.5 btc")
    >>> verify(pk, b"pay alice 0.5 btc", sig)
    True
    >>> verify(pk, b"pay mallory 0.5 btc", sig)
    False
"""

import hashlib
import random
import sys

N = 256          # security bits (hash output length)
SECRET_LEN = 32  # bytes per secret


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _bits(digest: bytes) -> list:
    """Expand a 32-byte digest into 256 bits, MSB first."""
    out = []
    for byte in digest:
        for shift in range(7, -1, -1):
            out.append((byte >> shift) & 1)
    return out


def gen_keypair(rng=None):
    """Generate a Lamport keypair.

    Returns (sk, pk) where sk[i][b] / pk[i][b] are the b-th secret / public
    value for bit position i. Public values are SHA-256(secret).

    >>> sk, pk = gen_keypair(random.Random(3))
    >>> len(sk) == len(pk) == N
    True
    >>> pk[0][0] == _sha256(sk[0][0])
    True
    """
    rng = rng or random.SystemRandom()
    sk = [[rng.getrandbits(SECRET_LEN * 8).to_bytes(SECRET_LEN, "big"),
           rng.getrandbits(SECRET_LEN * 8).to_bytes(SECRET_LEN, "big")]
          for _ in range(N)]
    pk = [[_sha256(sk[i][b]) for b in (0, 1)] for i in range(N)]
    return sk, pk


def sign(sk, message: bytes):
    """Sign a message: reveal the secret matching each digest bit of SHA256(msg)."""
    bits = _bits(_sha256(message))
    return [sk[i][bits[i]] for i in range(N)]


def verify(pk, message: bytes, sig):
    """Verify: every revealed secret must hash to the public value for that bit."""
    if len(sig) != N or len(pk) != N:
        return False
    bits = _bits(_sha256(message))
    return all(_sha256(sig[i]) == pk[i][bits[i]] for i in range(N))


def leakage_demo(rng_seed=7):
    """Sign TWO messages with the same key and show how much secret leaks.

    For each bit position where the two digests differ, the attacker learns
    the secret for the *opposite* bit of the second message, so part of a
    forged signature can already be assembled.

    >>> leaked = leakage_demo()  # doctest: +ELLIPSIS
    positions differing: ...
    >>> 0 < leaked < 256          # some, not all, positions leak per message pair
    True
    """
    rng = random.Random(rng_seed)
    sk, pk = gen_keypair(rng)
    m1, m2 = b"tx one", b"tx two"
    s1, s2 = sign(sk, m1), sign(sk, m2)
    b1, b2 = _bits(_sha256(m1)), _bits(_sha256(m2))
    leaked = sum(1 for i in range(N) if b1[i] != b2[i])  # s1[i] covers b2's opposite bit
    assert verify(pk, m1, s1) and verify(pk, m2, s2)
    # Forgeable forged-signature coverage: positions where s1 leaks m2's
    # opposite-bit secret are positions where attacker lacks m2's bit secret.
    still_secret = sum(1 for i in range(N) if b1[i] == b2[i])
    print(f"positions differing: {leaked}, positions still secret: {still_secret}")
    return leaked


if __name__ == "__main__":
    if "--test" in sys.argv:
        import doctest
        results = doctest.testmod(verbose=False)
        print(f"doctests: {results.attempted} run, {results.failed} failed")
        sys.exit(1 if results.failed else 0)
    if "--demo" in sys.argv:
        rng = random.Random(7)
        sk, pk = gen_keypair(rng)
        msg = b"pay alice 0.5 btc"
        sig = sign(sk, msg)
        print("verify ok:", verify(pk, msg, sig))
        print("verify tampered:", verify(pk, b"pay mallory 0.5 btc", sig))
        leakage_demo()
    else:
        print("usage: python3 lamport.py [--demo | --test]")
