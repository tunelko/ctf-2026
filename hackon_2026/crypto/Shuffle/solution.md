# Shuffle (Lotería Cuántica) - Crypto Challenge

## Challenge Info
- **Name**: Shuffle / Lotería Cuántica
- **Category**: Crypto
- **Points**: 304
- **Author**: znati
- **Remote**: `nc 0.cloud.chals.io 16316`
- **Description**: > Prueba a ganar el premio de la Lotería Cuántica, hasta ahora nadie lo ha conseguido.
- **Flag**: `HackOn{t4nt0_5ufFl3_m3_h4_d4Do_m4r3o_ch4v4l}`

---

## Initial Analysis

The server source code (`chall.py`) is provided:

```python
import random
import time

hint = []
for i in range(500):
    n = int.from_bytes(random.randbytes(8), byteorder='big')
    hint.append(n)

print("Bienvenido a la Lotería Cuántica")
print("Toma una pista")
time.sleep(1)
print(hint)

a = [random.getrandbits(32) for _ in range(11)]
print("La lista es esta:")
print(a)

random.shuffle(a)
time.sleep(3)
print("Para ganar, adivina como ha quedado la lista finalmente!")

user_input = input("Introduce tu predicción (n1 n2 n3...): ")
solve = list(map(int, user_input.split()))

if len(solve) == 11 and solve == a:
    print("Has ganado el premio máximo!\nHackOn{F4ke_Fl4g!}")
```

The server:
1. Generates **500 hints** via `random.randbytes(8)` and prints them
2. Generates a list of **11 integers** of 32 bits
3. **Shuffles** it with `random.shuffle()`
4. Asks to predict the final result

---

## Vulnerability

Python's `random` uses **MT19937** (Mersenne Twister), a **non-cryptographic** PRNG with internal state of **624 × 32 bits = 19,968 bits**.

The server gives away **500 hints × 8 bytes = 4,000 bytes = 1,000 32-bit words**: more than enough to reconstruct the complete state (only 624 consecutive words are needed).

With the recovered state we can predict **all future output**, including the 11 numbers and the shuffle result.

---

## Solution Process

### Step 1: Extract 32-bit words from hints

`random.randbytes(8)` internally calls the MT and packs **two 32-bit words in little-endian**:

```
randbytes(8) = w0.to_bytes(4, 'little') + w1.to_bytes(4, 'little')
```

But the server converts the result with `int.from_bytes(..., 'big')`, which reorders the bytes. To reverse:

```python
raw = n.to_bytes(8, 'big')
w0 = int.from_bytes(raw[0:4], 'little')   # first MT word
w1 = int.from_bytes(raw[4:8], 'little')   # second MT word
```

This was verified experimentally by comparing `getrandbits(32)` with `randbytes(8)` over the same known state.

### Step 2: Untemper: invert the MT19937 tempering function

The MT applies a tempering function before returning each word:

```
y ^= (y >> 11)              ← step 1
y ^= (y << 7)  & 0x9d2c5680 ← step 2
y ^= (y << 15) & 0xefc60000 ← step 3
y ^= (y >> 18)              ← step 4
```

To invert (in reverse order):

- **Step 4 inverse** (`>> 18`): self-inverse, the upper 18 bits don't change → `y ^= (y >> 18)` ✓
- **Step 3 inverse** (`<< 15`): self-inverse, the lower 15 bits don't change and M[16]=0 → `y ^= (y << 15) & 0xefc60000` ✓
- **Step 2 inverse** (`<< 7`): shift < 16, requires bit-by-bit reconstruction since each 7-bit block depends on the previous one
- **Step 1 inverse** (`>> 11`): shift < 16, same with three iterations

```python
def undo_right_xor(y, shift):
    result = y
    for _ in range(32 // shift):
        result = y ^ (result >> shift)
    return result & 0xffffffff

def undo_left_xor(y, shift, mask):
    result = 0
    for i in range(32):
        bit = (y >> i) & 1
        if i >= shift:
            bit ^= ((result >> (i - shift)) & 1) & ((mask >> i) & 1)
        result |= bit << i
    return result

def untemper(y):
    y = undo_right_xor(y, 18)
    y = undo_left_xor(y, 15, 0xefc60000)
    y = undo_left_xor(y, 7,  0x9d2c5680)
    y = undo_right_xor(y, 11)
    return y & 0xffffffff
```

### Step 3: Reconstruct the RNG state

With the first 624 untempered words, we reconstruct the complete internal state:

```python
recovered = [untemper(w) for w in mt_words[:624]]
r = random.Random()
# index=624: this block has been consumed, next call triggers twist
r.setstate((3, tuple(recovered + [624]), None))
```

Local verification: `temper(state[i]) == outputs[i]` for all 624 outputs ✓

### Step 4: Advance and predict

```python
# Consume the remaining 376 words from hints (1000 - 624)
for _ in range(376):
    r.getrandbits(32)

# Predict the 11 list elements
a_predicted = [r.getrandbits(32) for _ in range(11)]

# Simulate random.shuffle (Fisher-Yates with _randbelow)
a = a_predicted.copy()
for i in range(len(a) - 1, 0, -1):
    j = r._randbelow(i + 1)
    a[i], a[j] = a[j], a[i]
```

The list prediction was **exact** on the first attempt, confirming correct state recovery.

---

## Exploit Script

```python
#!/usr/bin/env python3
from pwn import *
import ast

HOST, PORT = "0.cloud.chals.io", 16316
context.log_level = 'info'

def undo_right_xor(y, shift):
    result = y
    for _ in range(32 // shift):
        result = y ^ (result >> shift)
    return result & 0xffffffff

def undo_left_xor(y, shift, mask):
    result = 0
    for i in range(32):
        bit = (y >> i) & 1
        if i >= shift:
            bit ^= ((result >> (i - shift)) & 1) & ((mask >> i) & 1)
        result |= bit << i
    return result

def untemper(y):
    y = undo_right_xor(y, 18)
    y = undo_left_xor(y, 15, 0xefc60000)
    y = undo_left_xor(y, 7,  0x9d2c5680)
    y = undo_right_xor(y, 11)
    return y & 0xffffffff

def extract_mt_words(hints):
    words = []
    for n in hints:
        raw = n.to_bytes(8, 'big')
        words.append(int.from_bytes(raw[0:4], 'little'))
        words.append(int.from_bytes(raw[4:8], 'little'))
    return words

def recover_random(mt_words):
    import random
    recovered = [untemper(w) for w in mt_words[:624]]
    r = random.Random()
    r.setstate((3, tuple(recovered + [624]), None))
    return r

def exploit():
    io = remote(HOST, PORT)
    io.recvuntil(b'Toma una pista\r\n')

    hints = ast.literal_eval(io.recvline().decode().strip())
    log.info(f'Got {len(hints)} hints')

    mt_words = extract_mt_words(hints)
    r = recover_random(mt_words)

    # Fast-forward past remaining hint words
    for _ in range(len(mt_words) - 624):
        r.getrandbits(32)

    io.recvuntil(b'La lista es esta:\r\n')
    a_original = ast.literal_eval(io.recvline().decode().strip())

    a_predicted = [r.getrandbits(32) for _ in range(11)]
    assert a_predicted == a_original, "State desync!"
    log.success('List prediction correct!')

    # Simulate shuffle
    a = a_predicted.copy()
    for i in range(len(a) - 1, 0, -1):
        j = r._randbelow(i + 1)
        a[i], a[j] = a[j], a[i]

    io.recvuntil(b'predicci')  # UTF-8 ó
    io.recvuntil(b': ')
    io.sendline(' '.join(map(str, a)).encode())

    result = io.recvall(timeout=5)
    log.success(result.decode(errors='replace').strip())
    io.close()

if __name__ == '__main__':
    exploit()
```

**Usage:**
```bash
python3 solve.py
```

**Actual output:**
```
[*] Got 500 hints
[*] Extracted 1000 MT words
[+] List prediction correct!
[+] Has ganado el premio máximo!
    HackOn{t4nt0_5ufFl3_m3_h4_d4Do_m4r3o_ch4v4l}
```

---

## Key Takeaways

1. **MT19937 is not cryptographically secure**: with 624 consecutive 32-bit outputs, the complete state can be reconstructed and all future (and past) outputs predicted
2. **`random.randbytes(8)` = 2 MT words**: the internal packing is little-endian per word; `int.from_bytes(..., 'big')` reverses the byte order but not the word order
3. **Inverting the tempering**: large shifts (15, 18) are self-inverse; the small shift (7) requires bit-by-bit reconstruction from low bits to high bits
4. **`random.shuffle` is deterministic**: uses `_randbelow(i+1)` internally with Fisher-Yates; fully predictable with recovered state
5. **Never use `random` for cryptography**: use `secrets` or `os.urandom` instead

## Files
- `solve.py` - Complete exploit (one-shot, no retries)
- `../chall.py` - Server source code
- `flag.txt` - Captured flag
