# Leaked Password Database — upCTF 2026

**Category:** Misc (Steganography / Statistics)
**Flag:** `upCTF{m4rk0v_w4s_h3r3_4ll_4l0ng}`

## TL;DR

4000 "passwords" of uppercase noise with a contiguous block of 25 signal characters (lowercase/digits/underscore) per line. The 25 positions of the block act as columns with a skewed distribution: the most frequent character in each column forms the flag.

---

## Analysis

### File structure

```
passwords.txt: 4000 lines, ~5K-12K characters each
Composition: ~99% UPPERCASE A-Z (uniform), ~1% signal (a-z, 0-9, _)
```

### Key findings

1. **25 signal chars per line**, always **contiguous** (consecutive block)
2. Total: 4000 × 25 = 100,000 signal characters
3. The block position varies per line (range 2500-6000)

### Frequency analysis by column

Forming a 4000×25 matrix with the signal blocks:

| Column | Most frequent char | Count | 2nd most frequent | Count | Ratio |
|---------|-------------------|-------|-------------------|-------|-------|
| 0 | m | 562 | b | 116 | 4.84 |
| 1 | 4 | 569 | z | 115 | 4.95 |
| 2 | r | 550 | h | 121 | 4.55 |
| ... | ... | ... | ... | ... | ... |
| 24 | g | 443 | n | 181 | 2.45 |

Under a uniform distribution (37 possible chars), we would expect ~108 per char. The dominant chars appear 4-5x more than the rest — a clear statistical signal.

---

## Vulnerability

**CWE-*** — Information hidden in skewed statistical distribution (statistical steganography).

The "noise" is not noise: each column of the signal block is generated with a Markov distribution (or simply biased) where one character has probability ~14% vs ~2.7% for the other 36.

---

## Exploit

### solve.py

```python
#!/usr/bin/env python3
from collections import Counter

with open("passwords.txt") as f:
    lines = f.readlines()

signals = []
for line in lines:
    line = line.strip()
    sig = [c for c in line if c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
    signals.append(sig)

flag = ""
for col in range(25):
    column = [s[col] for s in signals]
    most_common = Counter(column).most_common(1)[0][0]
    flag += most_common

print(f"upCTF{{{flag}}}")
```

```
$ python3 solve.py
upCTF{m4rk0v_w4s_h3r3_4ll_4l0ng}
```

---

## Discarded approaches

1. **Concatenate signal linearly**: 100K chars with no visible pattern
2. **Read by columns directly**: without looking at frequency, it appears random
3. **Signal block position**: varies but does not encode useful information (2500-6000, with duplicates)
4. **Sort by line length or position**: does not reveal a message

---

## Key Lessons

1. **Statistical steganography**: the signal is not in the data itself, but in the *distribution* of the data
2. **Frequency analysis by column**: when you have hidden tabular data, analyzing frequencies by position reveals biases
3. **"Markov" in the flag**: confirms the generator uses Markov chains with transitions biased toward a target character
4. **25 contiguous chars**: the contiguous block makes it easy to identify the "columns" — without this, the problem would be significantly harder

## References

- [Steganographic techniques in password databases](https://en.wikipedia.org/wiki/Steganography)
- [Markov chain text generation](https://en.wikipedia.org/wiki/Markov_chain#Text_generation)
