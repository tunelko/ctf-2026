# Protocol Analysis 3: Missing — DawgCTF 2026 (MISC)

## TL;DR
Alice is absent. Craft her message and send it directly to Bob.

## Protocol
```
Bob → recv: "Hello",B,"this is",A,"give me the flag"
       send: "here it is",[FLAG]
```

## Attack
No Alice in the protocol — we craft her expected message and send it to Bob ourselves. Bob has no way to verify the sender's identity.

## Flag
```
DawgCTF{N0_0N3_3LS3_H0M3}
```
