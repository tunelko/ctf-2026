# Mersenne Roulette — Crypto

> "The electronic roulette uses a Mersenne Oracle with 624 internal spirits. A waitress whispers: 'The secret is 0xCAFEBABE'."

## Summary

Mersenne Twister (MT19937) prediction attack. The server uses Python's `random.Random()` (MT19937) and XORs each output with `0xCAFEBABE`. By collecting 624 outputs and using `randcrack`, we can clone the RNG's internal state and predict all future values.

**Flag:** `0xfun{m3rs3nn3_tw1st3r_unr4v3l3d}`

## Analysis

### Vulnerabilities

1. **MT19937 is predictable**: with 624 consecutive 32-bit outputs, the complete internal state of the RNG can be recovered.

2. **XOR with known key**: `obfuscated = raw ^ 0xCAFEBABE` is trivially reversible:
   ```python
   raw = obfuscated ^ 0xCAFEBABE
   ```

3. **Simple interactive server**:
   - Command `spin` -> returns an obfuscated output
   - Command `predict` -> asks to predict 10 raw values to win

### Attack

1. Collect 624 outputs with `spin`
2. Deobfuscate: `raw[i] = obfuscated[i] ^ 0xCAFEBABE`
3. Clone state with `randcrack`
4. Use `predict` and send 10 **raw** values (without XOR)

## Exploit

```python
#!/usr/bin/env python3
from pwn import *
from randcrack import RandCrack

XOR_KEY = 0xCAFEBABE

io = remote('chall.0xfun.org', 57779)
rc = RandCrack()

log.info("Collecting 624 outputs...")

# Collect 624 outputs
for i in range(624):
    io.recvuntil(b'> ')
    io.sendline(b'spin')

    obfuscated = int(io.recvline().decode().strip())
    raw = obfuscated ^ XOR_KEY
    rc.submit(raw)

    if (i + 1) % 100 == 0:
        log.info(f"Progress: {i+1}/624")

log.success("RNG state cloned!")

# Verify predictions
for i in range(5):
    pred_raw = rc.predict_getrandbits(32)
    pred_obf = pred_raw ^ XOR_KEY

    io.recvuntil(b'> ')
    io.sendline(b'spin')
    real_obf = int(io.recvline().decode().strip())

    match = "OK" if pred_obf == real_obf else "FAIL"
    log.info(f"Prediction {i+1}: {match}")

# Use predict command
io.recvuntil(b'> ')
io.sendline(b'predict')
io.recvuntil(b': ')

# Generate 10 RAW predictions (without XOR)
predictions = [str(rc.predict_getrandbits(32)) for _ in range(10)]
io.sendline(' '.join(predictions).encode())

# Receive flag
response = io.recvrepeat(timeout=2).decode()
log.success(response)

# Output:
# PERFECT! You've untwisted the Mersenne Oracle!
# 0xfun{m3rs3nn3_tw1st3r_unr4v3l3d}
```

## Execution

```
$ python3 roulette_solve.py
[*] Collecting 624 outputs...
[*] Progress: 100/624
[*] Progress: 200/624
[*] Progress: 300/624
[*] Progress: 400/624
[*] Progress: 500/624
[*] Progress: 600/624
[+] RNG state cloned!
[*] Testing predictions...
[*] Prediction 1: OK
[*] Prediction 2: OK
[*] Prediction 3: OK
[*] Prediction 4: OK
[*] Prediction 5: OK
[+] PERFECT! You've untwisted the Mersenne Oracle!
    0xfun{m3rs3nn3_tw1st3r_unr4v3l3d}
```

## Tools

### randcrack

```bash
pip install randcrack
```

```python
from randcrack import RandCrack

rc = RandCrack()
for i in range(624):
    rc.submit(raw_output[i])

# Predict future values
next_val = rc.predict_getrandbits(32)
```

## Key Insight

The server asked for "Predict next 10 **raw** values" - meaning the values **before** XOR, not after. This is the crucial detail that makes the challenge work.

## Lessons Learned

1. **MT19937 is not cryptographically secure**: never use Python's `random.Random()` for security. Use `secrets` or `os.urandom()`.

2. **624 outputs = game over**: with only 624 consecutive 32-bit outputs, the MT19937 state can be completely cloned.

3. **XOR with known key is useless**: for obfuscation, an unknown key or real encryption is needed.

4. **`randcrack` is the standard tool**: implementing untemper manually is error-prone.

## References

- [randcrack](https://github.com/tna0y/Python-random-module-cracker)
- [Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister)
- Python `random` [docs](https://docs.python.org/3/library/random.html) - security warning
