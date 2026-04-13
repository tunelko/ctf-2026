# Protocol Analysis 8: Reflection — DawgCTF 2026 (MISC)

## TL;DR
Cross-wire attack: send Bob's identity to Alice and Alice's identity to Bob. Alice signs a message containing Bob's nonce, which satisfies Bob's verification.

## Protocol (both entities same role)
```
Alice: send pub_A,A,cert_A → recv pub_X,X,cert_X,n_X1 → send n_A,{X,n_X1,n_A}_{priv_A} → recv n_X2,{A,n_A,n_X2}_{priv_X}
Bob:   send pub_B,B,cert_B → recv pub_A,A,cert_A,n_A  → send n_B,{A,n_A,n_B}_{priv_B}  → recv n_A2,{A,n_B,n_A2}_{priv_A} → send FLAG
```

## Attack
1. B1: get pub_B, bob, cert_B
2. A1: get pub_A, alice, cert_A
3. B2: send (pub_A, alice, cert_A, fake_n) → Bob sends n_B + {alice, fake_n, n_B}_{priv_B}
4. A2: send (pub_B, bob, cert_B, n_B) → Alice sends n_A + **{bob, n_B, n_A}_{priv_A}**
5. B4: send (n_A, Alice's signature) → Bob verifies → **FLAG!**

## Key Insight
Bob's B4 verification `{A, n_B, n_A2}_{priv_A}` checks that the signature:
- Is signed by priv_A ✓ (Alice signed it)
- Contains n_B ✓ (Alice was given n_B in step A2)
- Bob does NOT check that the name field is "alice" — "bob" is accepted!

The "Reflection" is cross-wiring: each entity's output is fed as input to the other.

## Flag
```
DawgCTF{4SK_4ND_U_SH4LL_R3C31V3}
```
