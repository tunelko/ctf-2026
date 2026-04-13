# Protocol Analysis 6: Sneedham-Chucker — DawgCTF 2026 (MISC)

## TL;DR
Needham-Schroeder protocol with PKI certs. Classic Lowe attack: MITM both sides to recover both nonces, then derive the symmetric key to decrypt the flag.

## Protocol (Sneed = Alice, Chuck = Bob)
```
                                              Bob sends: pub_B, B, cert_B
Alice recv: pub_X, X, cert_X
Alice send: {n_A, pub_A, A, cert_A}_{pub_X}
                                              Bob recv: {n_A, pub_A, A, cert_A}_{pub_B}
                                              Bob send: {n_A, n_B}_{pub_A}
Alice recv: {n_A, n_X}_{pub_A}
Alice send: {n_X}_{pub_X}
                                              Bob recv: {n_B}_{pub_B}
                                              Bob send: {FLAG}_{h(n_A+n_B)}
Alice recv: {FLAG}_{h(n_A+n_X)}
```

## Attack (Lowe's MITM on Needham-Schroeder)
1. Generate own keypair + cert for name "mallory"
2. Intercept Bob's pub_B, send our pub_X to Alice
3. Alice encrypts {n_A, pub_A, cert_A} under our key → we decrypt → get n_A
4. Re-encrypt same payload under pub_B → forward to Bob
5. Bob sends {n_A, n_B}_{pub_A} → forward blindly to Alice (can't decrypt)
6. Alice decrypts, sends {n_B}_{pub_X} (our key) → we decrypt → get n_B
7. Re-encrypt n_B under pub_B → Bob verifies → sends encrypted flag
8. Compute key = h(n_A || n_B), nonce = first 12 bytes of key, decrypt flag

## Key Insight
Needham-Schroeder doesn't bind the nonce exchange to a specific peer identity. Alice willingly returns n_B encrypted under our key because she can't tell we're relaying to Bob.

## Flag
```
DawgCTF{FORM3RLY_S3CUR3}
```
