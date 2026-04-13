# Protocol Analysis 5: Is This Real? — DawgCTF 2026 (MISC)

## TL;DR
MITM public key substitution. Replace Alice's pub key with ours, Bob encrypts flag under our key, we decrypt with our private key.

## Protocol
```
Alice → send: "Hello",B,"this is",A,"send the flag encrypted under this asymmetric key",pub_A
Bob   → recv: same but with pub_X, then send: "here it is",{FLAG}_{pub_X}
Alice → recv: "here it is",{FLAG}_{pub_A}
```

## Attack
Classic MITM on unauthenticated key exchange:
1. Generate our own keypair (pub_X, priv_X) via `/util/gen_asym_key_pair`
2. Intercept Alice's message, replace `pub_A` with `pub_X`
3. Bob encrypts FLAG under `pub_X`
4. Decrypt with `priv_X` via `/util/asym_decrypt`

No certificates or authentication — Bob blindly trusts the public key in the message.

## Flag
```
DawgCTF{C3RT1F13D_1NS3CUR3}
```
