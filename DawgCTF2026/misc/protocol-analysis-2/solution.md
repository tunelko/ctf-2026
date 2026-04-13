# Protocol Analysis 2: Liar — DawgCTF 2026 (MISC)

## TL;DR
Bob only sends the flag to charlie. MITM: replace `n:alice` with `n:charlie` in the forwarded message.

## Protocol
```
Alice → send: "Hello",B,"this is",A,"give me the flag"
Bob   → recv: "Hello",B,"this is",C,"give me the flag"   ← expects charlie
        send: "here it is",[FLAG]
Alice → recv: "here it is",[FLAG]
```

## Attack
Intercept Alice's message and change the identity field from `n:alice` to `n:charlie` before forwarding to Bob. No authentication — Bob trusts whatever name is in the message.

## Flag
```
DawgCTF{CH4NG3_0F_PL4N5}
```
