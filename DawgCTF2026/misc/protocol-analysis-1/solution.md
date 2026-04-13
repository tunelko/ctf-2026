# Protocol Analysis 1: Can You Hear Me? — DawgCTF 2026 (MISC)

## TL;DR
Simple message relay between Alice and Bob. No crypto, no auth — just pass messages through.

## Protocol
```
Alice → send: "Hello",B,"this is",A,"give me the flag"
Bob   → recv: same, then send: "here it is",[FLAG]
Alice → recv: "here it is",[FLAG]
```

## Attack
No attack needed — just relay messages faithfully. The flag is in plaintext in Bob's response.

## Flag
```
DawgCTF{PR0T0C0LS_R_3ZPZ}
```
