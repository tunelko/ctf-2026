# Validator — EHAXctf Reversing

**Category:** Reversing
**Description:** "The computation prof gave me some data and an executable, what does he want from me?"
**Files:** `validator` (ELF 64-bit), `signal_data.txt` (2600 coordinates)
**Flag:** `EH4X{n3WT0n_W45_R1GHT}`

---

## Initial Analysis

```
$ file validator
validator: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped

$ checksec --file=validator
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled

$ wc -l signal_data.txt
2600 signal_data.txt

$ head -3 signal_data.txt
0.3745401188473625,0.9507143064099162
0.7319939418114051,0.5986584841970366
0.15601864044243652,0.15599452033620265
```

Not stripped binary, 2600 pairs of coordinates (x, y) representing complex numbers.

## Binary Reversing

The binary takes two arguments (real, imag) and runs **Newton's method** for the function `f(z) = z^3 - 1`:

```
Usage: ./validator <real> <imag>
```

### Algorithm (extracted from main disassembly):

1. Converts arguments to doubles via `atof()`
2. Runs Newton iterations (max 50):
   - `f(z) = z^3 - 1` → real and imaginary parts
   - `f'(z) = 3z^2` → complex derivative
   - `z_{n+1} = z_n - f(z_n) / f'(z_n)` → Newton step
3. Early exit condition: `|f'(z)|^2 < 1e-9`
4. Convergence: `|Re(z) - 1| < 1e-6 AND |Im(z)| < 1e-6` (root z=1)
5. **Accepts the point if it converges in EXACTLY 12 iterations**

### Constants extracted from binary:
| Address | Value | Usage |
|---------|-------|-------|
| 0x20d0 | 3.0 | Coefficients of f'(z) |
| 0x20d8 | 1.0 | Target root, f(z) constant |
| 0x20e0 | 6.0 | Imaginary part of f'(z) |
| 0x20e8 | 1e-9 | Denominator threshold |
| 0x20f0 | 1e-6 | Convergence threshold |

### Verification:
```
$ ./validator 0.3745401188473625 0.9507143064099162
AUTHORIZATION DENIED: Invalid Node.

$ ./validator -0.40369583792498475 0.5765181233208498  # valid point
AUTHORIZATION ACCEPTED: Node Valid.
```

## Trick

No memory vulnerability. This is a **pure analysis** challenge:

1. Reimplement Newton's method in Python
2. Classify each point as VALID (12 iters) or INVALID
3. Interpret the 2600 binary results (1/0) as a **bitmap**
4. Find the correct grid dimensions that render readable text

## Solution Steps

### Step 1: Reimplement the validator
```python
def newton_z3(x0, y0):
    x, y = x0, y0
    iters = 0
    for i in range(50):
        fx = x**3 - 3*x*y**2 - 1
        fy = 3*x**2*y - y**3
        dpx = 3*(x**2 - y**2)
        dpy = 6*x*y
        denom = dpx**2 + dpy**2
        if denom < 1e-9:
            break
        step_x = (fx*dpx + fy*dpy) / denom
        step_y = (fy*dpx - fx*dpy) / denom
        x -= step_x
        y -= step_y
        iters += 1
        if abs(x - 1.0) < 1e-6 and abs(y) < 1e-6:
            break
    return iters
```

### Step 2: Classify all 2600 points
- **226 points** converge in exactly 12 iterations → bit "1"
- **2374 points** don't meet the condition → bit "0"

### Step 3: Find grid dimensions
2600 has multiple factorizations:
```
1x2600, 2x1300, 4x650, 5x520, 8x325, 10x260,
13x200, 20x130, 25x104, 26x100, 40x65, 50x52
```

Testing each one, **130x20** (130 columns, 20 rows) produces readable text in a 5-row-high bitmap font:

```
████ █  █ █  █ █  █   ██ ███  ████ █   █ ███  ██  ███       █   █ █  █ ████       ████   █  ████ █  █ ███   ██
█    █  █ █  █  ██   ██  █  █    █ █   █  █  █  █ █  █      █   █ █  █ █          █  █  ██  █    █  █  █   ██
███  ████ ████   █   █   █  █  ███ █ █ █  █  █  █ █  █ ████ █ █ █ ████ ███  ████  ███    █  █ ██ ████  █   █
█    █  █    █  ██   ██  █  █    █ ██ ██  █  █  █ █  █      ██ ██    █    █       █ █    █  █  █ █  █  █   ██
████ █  █    █ █  █   ██ █  █ ████ █   █  █   ██  █  █      █   █    █ ████       █  █ ████ ████ █  █  █    ██
```

### Step 4: Decode characters
Segmenting by empty columns yields 22 glyphs in 5x4 bitmap font:

**Result: `EH4X{n3WT0n_W45_R1GHT}`**

Decoded message: **NEWTON WAS RIGHT** (in leet speak)

## Exploit Script (solve.py)

```python
#!/usr/bin/env python3
"""Validator solver — Newton's method bitmap decoder"""

def newton_z3(x0, y0):
    x, y = x0, y0
    iters = 0
    for i in range(50):
        fx = x**3 - 3*x*y**2 - 1
        fy = 3*x**2*y - y**3
        dpx = 3*(x**2 - y**2)
        dpy = 6*x*y
        denom = dpx**2 + dpy**2
        if denom < 1e-9:
            break
        step_x = (fx*dpx + fy*dpy) / denom
        step_y = (fy*dpx - fx*dpy) / denom
        x -= step_x
        y -= step_y
        iters += 1
        if abs(x - 1.0) < 1e-6 and abs(y) < 1e-6:
            break
    return iters

# Load signal data
with open("signal_data.txt") as f:
    points = [tuple(map(float, line.strip().split(','))) for line in f if line.strip()]

# Classify: 1 if exactly 12 iterations
bits = [1 if newton_z3(x, y) == 12 else 0 for x, y in points]

# Render as 130x20 grid
W, H = 130, 20
for row in range(H):
    line = ""
    for col in range(W):
        line += "█" if bits[row * W + col] else " "
    print(line)
```

## Flag

```
EH4X{n3WT0n_W45_R1GHT}
```

## Key Lessons

1. **Newton fractals as encoding**: Newton fractals for z^3-1 have three roots (cube roots of unity). The number of iterations to converge varies per starting point, creating a fractal. The challenge uses this property for binary point classification.

2. **Factorization for bitmap dimensions**: With 2600 bits, there are 12 possible factorizations. The key is trying each one and looking for readable patterns. Only 130x20 shows clear text.

3. **5-row bitmap fonts**: Characters render in a monospace font 5 rows high and 3-5 columns wide, separated by empty columns. Segmenting by empty columns isolates each glyph.

4. **Thematic context**: The challenge hints ("computation prof", "signal data", "validator") point to computational mathematics. Newton's method for complex polynomials is a classic numerical analysis topic.

## Files

```
reversing/validator/
├── validator          # ELF 64-bit binary (Newton method validator)
├── signal_data.txt    # 2600 coordinates (x,y)
├── solve.py           # Complete solver
├── flag.txt           # Captured flag
└── solution.md        # This writeup
```
