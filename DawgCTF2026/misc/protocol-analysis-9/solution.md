# Protocol Analysis 9: Oracle — DawgCTF 2026 (MISC)

## TL;DR
Alice is a decryption oracle that loops infinitely. Three-round attack: peel outer encryption, extract inner encrypted flag, feed back to Alice for final decryption.

## Protocol
```
Alice send: pub_A, A, cert_A
Bob   recv: pub_A, A, cert_A
      send: pub_B, B, cert_B, {{FLAG}_{pub_A}, B}_{pub_A}, A

Alice loops:
  recv: pub_X, X, cert_X, {{m}_{pub_A}, X}_{pub_A}, A
  send: pub_A, A, cert_A, {{m}_{pub_X}, A}_{pub_X}, X
```

Alice decrypts both layers of the double-encrypted blob (using priv_A) and re-encrypts under pub_X.

## Key Insight
- `asym_encrypt(pub_key, text)` encrypts with public key (standard RSA)
- We CAN encrypt under pub_A ourselves using the utility
- Alice checks inner name matches claimed identity X

## Attack (3 rounds)

**Round 1**: Forward Bob's blob to Alice as X=bob (Bob's real pub+cert)
- Alice decrypts, re-encrypts under pub_B → we can't decrypt (no priv_B)
- Purpose: confirms the protocol works

**Round 2**: Wrap Bob's ENTIRE blob as an inner layer in a new outer
- Craft: `asym_encrypt(pub_A, "BOB_BLOB|n:mallory")`
- Send to Alice as X=mallory (our cert)
- Alice decrypts outer → finds Bob's blob as "inner message"
- Alice decrypts Bob's blob → gets `{FLAG}_{pub_A}|n:bob`
- Alice re-encrypts under pub_mallory
- We decrypt → get `{FLAG}_{pub_A}|n:bob`
- Extract `{FLAG}_{pub_A}` (flag still encrypted under pub_A)

**Round 3**: Feed extracted `{FLAG}_{pub_A}` back as inner
- Craft: `asym_encrypt(pub_A, "{FLAG}_{pub_A}|n:mallory")`
- Send to Alice as X=mallory
- Alice decrypts outer → finds `{FLAG}_{pub_A}` and "mallory"
- Alice decrypts inner → gets FLAG (plaintext!)
- Alice re-encrypts under pub_mallory
- We decrypt → **FLAG!**

## Flag
```
DawgCTF{ST4R3_1NTO_TH3_VO1D}
```
