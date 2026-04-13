# Protocol Analysis 4: Real Security! — DawgCTF 2026 (MISC)

## TL;DR
Alice sends symmetric key and nonce in plaintext. Intercept them, forward to Bob, decrypt his encrypted response.

## Protocol
```
Alice → send: "Hello",B,"this is",A,"send the flag encrypted with this symmetric key and nonce",k,n
Bob   → recv: same, then send: "here it is",{FLAG}_k
Alice → recv: "here it is",{FLAG}_k
```

## Attack
Classic key-in-the-clear flaw. As MITM we see Alice's key `k` and nonce `n` in transit. Forward the message to Bob, intercept his encrypted response, and use `/util/sym_decrypt` with the captured key to recover the flag.

## Flag
```
DawgCTF{N0T_S0_S3CR3T_K3Y}
```
