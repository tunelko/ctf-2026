# Batcave Bitflips — UMassCTF 2026 (REV)

## TL;DR
Binary has 3 "cosmic ray" bit flip bugs. Don't need to find them all — just XOR the encrypted FLAG with the EXPECTED hash to get the flag directly.

## Analysis
- Binary hashes a license key and compares with hardcoded EXPECTED (32 bytes)
- If match, decrypts FLAG (32 bytes) using the hash
- decrypt_flag uses OR (bug — should be XOR)
- The 3 bugs: SBOX corruption, rotate shift amount, OR instead of XOR in decrypt

## Shortcut
Since `verify()` checks `hash == EXPECTED`, and correct `decrypt_flag` does `FLAG[i] XOR hash[i]`:
```
plaintext = FLAG XOR EXPECTED
```
No need to fix the hash function or find the license key!

## Flag
```
UMASS{__p4tche5_0n_p4tche$__#}
```
