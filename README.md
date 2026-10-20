# lamport-ots

Lamport **one-time signatures** over SHA-256 in pure Python — zero dependencies.

Lamport signatures are the simplest hash-based signature scheme: no elliptic
curves, no number theory, just a hash function. A keypair is 256 pairs of
random secrets (public key = SHA-256 of each secret); signing reveals one
secret per message bit. They are quantum-resistant — but strictly one-time:
signing a second message with the same key leaks enough secrets to forge.

## What's here

- `lamport.py` — `gen_keypair`, `sign`, `verify`, plus a `leakage_demo`
  showing exactly how many key bits two signatures expose (why reuse breaks it)

## Try it

```bash
python3 lamport.py --demo   # sign, verify, tamper check, leakage demo
python3 lamport.py --test   # run the 11 doctests
```

## The idea in 30 seconds

- `sk[i][b]` — secret for bit position `i`, bit value `b` (512 × 32 bytes)
- `pk[i][b] = SHA256(sk[i][b])` — public key
- signature of `m` = `sk[i][bit_i(SHA256(m))]` for all `i`
- verify = check every revealed secret hashes to the published public value

Sign twice with the same key and ~half the unrevealed secrets leak — that's the
one-time contract.
