# The Slot Whisperer — Writeup

**Category:** Crypto
**Difficulty:** Easy/Medium
**Flag:** `0xfun{sl0t_wh1sp3r3r_lcg_cr4ck3d}`

## Description

We are provided with the source code of a slot machine (`slot.py`) and a remote service. The server shows us 10 machine results and we must predict the next 5.

## Analysis

### Source code

```python
class SlotMachineLCG:
    def __init__(self, seed=None):
        self.M = 2147483647   # 2^31 - 1 (Mersenne prime)
        self.A = 48271
        self.C = 12345
        self.state = seed if seed is not None else 1

    def next(self):
        self.state = (self.A * self.state + self.C) % self.M
        return self.state

    def spin(self):
        return self.next() % 100
```

It is a **classic LCG (Linear Congruential Generator)** with known parameters:

| Parameter | Value |
|-----------|-------|
| Modulus (M) | 2,147,483,647 (2^31 - 1) |
| Multiplier (A) | 48,271 |
| Increment (C) | 12,345 |

The visible output is `state % 100` -- only the **last 2 digits** of the internal state.

### Server interaction

```
70
8
90
52
82
85
89
52
27
12
Predict the next 5 spins (space-separated):
```

We receive 10 spins (values 0-99) and must predict the next 5.

## Vulnerability

The LCG has completely known parameters (A, C, M). We only don't know the **internal state** (`state`), which is an integer in the range `[0, M)`.

Since `spin = state % 100`, the actual state for the first spin is:

```
state_0 = output_0 + 100*k    for some k in [0, M/100]
```

This gives us ~21.4 million candidates. For each candidate, we just need to verify that applying the LCG, the following states also match `mod 100` with the observed outputs. With **early pruning** (discard as soon as the first check fails), the search is extremely fast.

### Complexity

- Search space: ~21.4M candidates
- Each candidate is discarded with probability 99/100 on the first check
- Total effective operations: ~21.4M + ~214K + ~2.1K ~ **21.6M simple operations**
- Real time: **~2-3 seconds** in Python

## Exploit

```python
#!/usr/bin/env python3
from pwn import *
import time

HOST = 'chall.0xfun.org'
PORT = 38672

M = 2147483647
A = 48271
C = 12345

def find_state(outputs):
    """Brute force: state[0] = outputs[0] + 100*k"""
    o0, o1 = outputs[0], outputs[1]
    for k in range(M // 100 + 1):
        state = o0 + 100 * k
        if state >= M:
            break
        # Quick check against output[1]
        s = (A * state + C) % M
        if s % 100 != o1:
            continue
        # Verify the rest of the outputs
        match = True
        for i in range(2, len(outputs)):
            s = (A * s + C) % M
            if s % 100 != outputs[i]:
                match = False
                break
        if match:
            return state
    return None

# Connect and parse
p = remote(HOST, PORT, timeout=15)
data = p.recvuntil(b'separated): ', timeout=15)
seq = []
for line in data.decode().strip().split('\n'):
    try:
        val = int(line.strip())
        if 0 <= val <= 99:
            seq.append(val)
    except:
        pass

# Recover internal state
state0 = find_state(seq)

# Advance to the end of the 10 observed and predict 5
s = state0
for _ in range(9):
    s = (A * s + C) % M
preds = []
for _ in range(5):
    s = (A * s + C) % M
    preds.append(s % 100)

# Send prediction
p.sendline(' '.join(map(str, preds)).encode())
print(p.recvall(timeout=10).decode())
p.close()
```

### Execution

```
[*] Sequence received (10): [94, 99, 26, 72, 18, 21, 35, 12, 92, 69]
[*] Searching for LCG state...
[+] State found: 976988794 (in 2.4s)
[+] Prediction: [77, 21, 54, 54, 54]
[*] Response: JACKPOT! You've mastered the slot machine!
    0xfun{sl0t_wh1sp3r3r_lcg_cr4ck3d}
```

## Key Concepts

- **LCG (Linear Congruential Generator):** Deterministic PRNG with formula `x_{n+1} = (A*x_n + C) mod M`. Completely predictable if the parameters are known.
- **Truncated output:** Seeing only `state % 100` reduces information, but with known parameters a brute force over the ~21M possible initial states is sufficient.
- **Early pruning:** Verifying against the second output immediately discards 99% of candidates, making the brute force practical.
