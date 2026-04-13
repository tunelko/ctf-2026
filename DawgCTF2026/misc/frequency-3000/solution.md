# Frequency 3000 — DawgCTF 2026 (MISC)

## TL;DR
Hex-encoded numbers in flag.txt map to character frequencies in the Futurama "Space Pilot 3000" transcript. Leet speak decodes to "why not zoidberg?"

## Analysis
1. `flag.txt` contains hex → decodes to: `DawgCTF{ 390 1002 580 1314 191 1589 33 1526 141 762 352 88 1293 379 50 }`
2. Each number = frequency count of a character in the transcript
3. Mix of case-insensitive letter frequencies and exact digit/punctuation frequencies

## Mapping
| Number | Freq of | Char |
|--------|---------|------|
| 390 | w | w |
| 1002 | h | h |
| 580 | y | y |
| 1314 | n (≈1315) | n |
| 191 | 0 (exact) | 0 |
| 1589 | t | t |
| 33 | z | z |
| 1526 | o (≈1528) | o |
| 141 | I (exact) | I |
| 762 | d | d |
| 352 | b | b |
| 88 | 3 (exact) | 3 |
| 1293 | r (≈1295) | r |
| 379 | g (≈380) | g |
| 50 | ? (exact) | ? |

## Flag
```
DawgCTF{whyn0tz0Idb3rg?}
```
