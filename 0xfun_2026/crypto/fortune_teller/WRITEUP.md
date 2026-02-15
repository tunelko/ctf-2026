# The Fortune Teller — Crypto (250pts, Medium)

> "It speaks in 64-bit truths but only reveals 32-bit glimpses. The constants are known. The seed is not. Suffering ends in 30 minutes."

## Summary

Cryptography challenge based on a **truncated LCG (Linear Congruential Generator)**. The generator works with 64-bit states but only reveals the upper 32 bits ("glimpses"). With 3 consecutive glimpses, the complete state can be recovered via parallel brute-force or using **LLL lattice reduction**.

**Flag:** `0xfun{trunc4t3d_lcg_f4lls_t0_lll}`

## Challenge Analysis

### Files provided

```
fortune.py          # FortuneTeller implementation
```

### The FortuneTeller generator

```python
class FortuneTeller:
    def __init__(self, seed=None):
        self.M = 2**64
        self.A = 2862933555777941757
        self.C = 3037000493
        self.state = seed if seed is not None else random.randint(1, self.M - 1)

    def next(self):
        self.state = (self.A * self.state + self.C) % self.M
        return self.state

    def glimpse(self):
        full = self.next()
        return full >> 32  # Only returns the upper 32 bits
```

It is a **classic LCG**:
- `state_{n+1} = (A * state_n + C) mod M`
- M = 2^64 (64-bit modulus)
- A = 2862933555777941757 (multiplier)
- C = 3037000493 (increment)

The `glimpse()` function only returns `state >> 32`, hiding the lower 32 bits.

### Server interaction

```bash
$ nc chall.0xfun.org 33137
778586380
1192801157
326720035
Predict the next 5 full 64-bit states (space-separated):
```

The server:
1. Generates a random seed
2. Gives us 3 **glimpses** (upper 32 bits of each state)
3. Asks to predict the next **5 full 64-bit states**

### Problem to solve

We have:
- `glimpse1 = state1 >> 32` (known)
- `glimpse2 = state2 >> 32` (known)
- `glimpse3 = state3 >> 32` (known)

Where:
- `state1 = (glimpse1 << 32) | low1` (low1 unknown, 32 bits)
- `state2 = (A * state1 + C) mod 2^64`
- `state3 = (A * state2 + C) mod 2^64`

**Goal:** Recover `low1` (the lower 32 bits of the first state) to be able to reconstruct all future states.

## Solution 1: Parallel brute-force (implemented)

### Strategy

With only 2^32 possible values (~4.3 billion), brute-force is feasible with parallelization:

1. For each possible value `low1` in [0, 2^32-1]:
   - Build `state1 = (glimpse1 << 32) | low1`
   - Compute `state2 = (A * state1 + C) mod 2^64`
   - Compute `state3 = (A * state2 + C) mod 2^64`
   - Check if `state2 >> 32 == glimpse2` AND `state3 >> 32 == glimpse3`
   - If it matches, we found the correct `low1`

2. With multiprocessing, split the search space across multiple cores

### Complexity

- **Search space:** 2^32 = 4,294,967,296 values
- **Time with 12 cores:** ~207 seconds (~3.5 minutes) in the test case
- **Time per check:** ~2 operations of 64 bits (very fast)

### Implementation

```python
from multiprocessing import Pool, cpu_count

M = 2**64
A = 2862933555777941757
C = 3037000493

def check_range(args):
    """Check a range of possible values for low1"""
    start, end, high1, high2, high3 = args

    for low1 in range(start, end):
        state1 = (high1 << 32) | low1
        state2 = (A * state1 + C) % M
        state3 = (A * state2 + C) % M

        if (state2 >> 32) == high2 and (state3 >> 32) == high3:
            return low1  # Found!

    return None

def recover_state_parallel(glimpses):
    high1, high2, high3 = glimpses

    # Split space among workers
    num_workers = cpu_count()
    chunk_size = (2**32) // num_workers

    ranges = []
    for i in range(num_workers):
        start = i * chunk_size
        end = start + chunk_size if i < num_workers - 1 else 2**32
        ranges.append((start, end, high1, high2, high3))

    # Run in parallel
    with Pool(num_workers) as pool:
        results = pool.map(check_range, ranges)

    # Find the result
    for low1 in results:
        if low1 is not None:
            state1 = (high1 << 32) | low1
            state2 = (A * state1 + C) % M
            state3 = (A * state2 + C) % M
            return state3  # Return the last known state

    return None
```

### Result

```
[*] Search completed in 206.92 seconds
[+] State recovered!
[+] state1 = 3344003041553305374
[+] low1 = 2342276894 (0x8b9c4f1e)
[*] Predictions:
[*]   State 1: 7857473038330087185
[*]   State 2: 10994534748763217658
[*]   State 3: 7451116242265878591
[*]   State 4: 734606603042189680
[*]   State 5: 14627432404067684061

IMPOSSIBLE! You've pierced the Fortune Teller's heart!
0xfun{trunc4t3d_lcg_f4lls_t0_lll}
```

## Solution 2: LLL Lattice Reduction (theoretical)

The flag `trunc4t3d_lcg_f4lls_t0_lll` suggests that the intended solution was to use the **LLL algorithm**.

### Mathematical foundation

Truncated LCGs are vulnerable to lattice-based attacks. The problem can be reformulated as:

Given:
- Multiple truncated outputs `y_i = floor(x_i / 2^k)` where `x_i` are LCG states
- The relation `x_{i+1} = (A * x_i + C) mod M`

Find:
- The full values `x_i` (64-bit states)

### Lattice construction

With n truncated outputs, we can build a lattice matrix that encodes:

1. The LCG equations: `x_{i+1} - A * x_i = C (mod M)`
2. The truncation constraints: `y_i <= x_i / 2^k < y_i + 1`

This construction creates a **CVP (Closest Vector Problem)** that can be solved with LLL.

### Lattice matrix (simplified)

For 3 glimpses, the matrix would be approximately 6x6:

```
[ M   0   0   2^32  0      0    ]
[ -A  M   0   0      2^32   0    ]
[ 0   -A  M   0      0      2^32 ]
[ 2^32 0  0   1      0      0    ]
[ 0   2^32 0  0      1      0    ]
[ 0   0  2^32 0      0      1    ]
```

The target vector would be:
```
(C, C, C, glimpse1 * 2^32, glimpse2 * 2^32, glimpse3 * 2^32)
```

### SageMath implementation

```sage
def solve_with_lll(glimpses, A, C, M=2**64):
    """
    Solve the truncated LCG using LLL lattice reduction
    """
    high1, high2, high3 = glimpses
    n = len(glimpses)

    # Build the lattice matrix
    # Dimension: (n + n) x (n + n)
    # First n rows: LCG equations with modulus M
    # Last n rows: truncation constraints

    dim = 2 * n
    L = Matrix(ZZ, dim, dim)

    # Rows 1-3: LCG equations
    L[0, 0] = M
    L[0, 3] = 2**32

    L[1, 0] = -A
    L[1, 1] = M
    L[1, 4] = 2**32

    L[2, 1] = -A
    L[2, 2] = M
    L[2, 5] = 2**32

    # Rows 4-6: identity for error variables
    for i in range(n):
        L[n + i, n + i] = 1
        L[n + i, i] = 2**32

    # Target vector (right-hand side of equations)
    target = vector(ZZ, [
        C + high1 * 2**32,
        C + high2 * 2**32,
        C + high3 * 2**32,
        0, 0, 0
    ])

    # Apply LLL
    L_reduced = L.LLL()

    # Find the closest vector to the target
    # (this is more complex, requires Babai's algorithm or CVP solver)

    # Extract the lower bits from the solution
    # ...

    return low1_recovered
```

### LLL complexity

- **Time:** O(n^5 * log^3 M) ~ polynomial
- For n=3, M=2^64: very fast (< 1 second with optimized implementation)
- **Advantage:** Much faster than brute-force in the worst case
- **Disadvantage:** More complex implementation

## Method comparison

| Method | Time | Complexity | Implementation |
|--------|------|------------|----------------|
| Serial brute-force | ~30-60 min | O(2^32) | Very simple |
| Parallel brute-force (12 cores) | ~3.5 min | O(2^32 / n_cores) | Simple |
| LLL lattice reduction | < 1 second | O(n^5 * log^3 M) | Complex (SageMath) |

## Full exploit

See `fortune_solve_fast.py` for the implemented parallel brute-force solution.

## Lessons Learned

1. **Truncated LCGs are vulnerable** even with just a few outputs:
   - With 3 glimpses (32 bits each), the full state is recoverable
   - The 32 hidden bits can be recovered in minutes with brute-force
   - With LLL, recovery is almost instantaneous

2. **Truncation does not provide cryptographic security:**
   - Hiding bits does not break the underlying linear relation
   - Lattices can exploit the linear structure of the LCG

3. **LCGs should NEVER be used for cryptography:**
   - They are predictable with mathematical analysis
   - Vulnerable to truncation attacks
   - Use `secrets` or `os.urandom()` instead

4. **Parallelization is effective for moderate search spaces:**
   - 2^32 is feasible with multiprocessing (minutes)
   - 2^40 would be borderline (hours)
   - 2^48+ requires more sophisticated approaches (LLL, GPU, etc.)

5. **The flag reveals the intended solution:**
   - `trunc4t3d_lcg_f4lls_t0_lll` confirms that LLL was the expected method
   - However, parallel brute-force is more straightforward for this search space size

## References

- [Truncated LCG Attacks](https://eprint.iacr.org/2019/1063.pdf)
- [LLL Algorithm - Wikipedia](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm)
- [Predicting LCGs with Lattices](https://www.math.cmu.edu/~af1p/Texfiles/RECONTRUNC.pdf)
- [SageMath LLL documentation](https://doc.sagemath.org/html/en/reference/matrices/sage/matrix/matrix_integer_dense.html#sage.matrix.matrix_integer_dense.Matrix_integer_dense.LLL)

## Note

This writeup documents the practical solution (parallel brute-force) which worked in ~3.5 minutes. The theoretically optimal solution would be to implement LLL lattice reduction in SageMath, which should solve the problem in less than 1 second. For CTF environments where time is critical, parallel brute-force is a pragmatic and effective solution for 2^32 search spaces.
