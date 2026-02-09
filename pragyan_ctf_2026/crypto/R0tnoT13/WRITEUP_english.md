# State Reconstruction - R0tnoT13

**Category:** Crypto
**Difficulty:** Medium
**Platform:** Pragyan CTF 2026
**Flag:** `p_ctf{l1nyrl34k}`

---

## Challenge Description

During a security audit of a custom cryptographic module, you obtain partial diagnostic logs from a faulty randomness subsystem.

The subsystem maintains an internal 128-bit state derived from AES, which is periodically inspected for integrity using bit-rotation consistency checks.

For specific, preconfigured rotation offsets k, the firmware records the value:

```
S ⊕ ROTR(S, k)
```

**Given:**
- Several leaked diagnostic frames of the form `S ⊕ ROTR(S, k)`
- The corresponding rotation offsets k
- A ciphertext encrypted using the internal state

**Objective:** Reconstruct the state and recover the flag.

---

## Challenge Data

```
== States ==
8  183552667878302390742187834892988820241
4  303499033263465715696839767032360064630
16 206844958160238142919064580247611979450
2  163378902990129536295589118329764595602
64 105702179473185502572235663113526159091
32 230156190944614555973250270591375837085

== Ciphertext (hex) ==
477eb79b46ef667f16ddd94ca933c7c0
```

---

## Analysis

### Understanding the Problem

The challenge provides values of `S ⊕ ROTR(S, k)` for various rotation offsets k. Each value gives information about bit relationships in state S.

For a 128-bit state, each equation `S ⊕ ROTR(S, k) = result` expands to 128 individual bit equations:
```
result[i] = S[i] ⊕ ROTR(S, k)[i]
```

### Rotation Semantics - Critical Discovery

Determining the correct rotation direction was critical:

- **ROTR (Rotate Right):** `ROTR(S, k)[i] = S[(i - k) mod 128]`
- **ROTL (Rotate Left):** `ROTL(S, k)[i] = S[(i + k) mod 128]`

Initial ROTR attempts produced an **inconsistent** system. Switching to **ROTL** made it consistent:

```
ROTL interpretation:
  Rank A: 126
  Rank [A|b]: 126
  ✓ CONSISTENT! Free variables: 2
```

### Linear System Structure

- **768 equations** (6 × 128)
- **128 variables** (state bits)
- **Rank = 126** (2 free variables at positions 126 and 127)
- **4 possible solutions** (2² combinations)

---

## Solution Approach

### Z3 SMT Solver

Used Z3 constraint solver for Boolean satisfiability:

```python
from z3 import *

S_bits = [Bool(f's_{i}') for i in range(128)]
solver = Solver()

for k, result_int in states.items():
    result_bits = int_to_bits(result_int)
    for i in range(128):
        lhs = Xor(S_bits[i], S_bits[(i + k) % 128])
        rhs = BoolVal(bool(result_bits[i]))
        solver.add(lhs == rhs)

if solver.check() == sat:
    model = solver.model()
    # Extract solution...
```

---

## Exploitation

### Step 1: Solve for State S

```bash
$ python3 solve_z3.py
Solving system with 768 constraints...
✓ Solution found!

State S (hex): 3721d4ef20940a4e78a4ab209a07acbd
```

### Step 2: Verify Solution

All 6 rotation equations verified correctly.

### Step 3: Decrypt Ciphertext

Tried multiple methods - correct decryption was **XOR with big-endian encoding**:

```python
key_bytes = S.to_bytes(16, 'big')
flag = bytes([ciphertext[i] ^ key_bytes[i] for i in range(16)])
# flag = b'p_ctf{l1nyrl34k}'
```

---

## Key Takeaways

1. **Rotation Direction Matters:** Description said ROTR, but implementation used ROTL. Verify conventions when system appears inconsistent.

2. **Rank Analysis is Critical:** Comparing ranks immediately reveals if solution exists.

3. **Z3 for Boolean Systems:** More reliable than manual Gaussian elimination for GF(2) systems.

4. **Multiple Decryption Methods:** Always try different schemes (AES-ECB, XOR) with both endianness options.

5. **Free Variables:** Underdetermined systems with n free variables have 2ⁿ solutions - use solvers to find the correct one.

---

## Solution Summary

**Reconstructed State:**
```
S = 0x3721d4ef20940a4e78a4ab209a07acbd
```

**Decryption:**
```
Ciphertext: 0x477eb79b46ef667f16ddd94ca933c7c0
Key (big-endian): 0x3721d4ef20940a4e78a4ab209a07acbd
Method: XOR
Flag: p_ctf{l1nyrl34k}
```

**Flag meaning:** "linear leak" - referring to linear equations leaked through XOR-rotation operations enabling state reconstruction.

---

## PoC

### Exploit Execution

<img src="rotnot13.png" alt="Exploit execution" width="800">

*Screenshot showing successful execution of Z3 solver, verification of all rotation equations, and flag decryption.*
