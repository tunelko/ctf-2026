# Beneath the Fourth Moon

**CTF:** Midnight Flag CTF 2026
**Category:** Crypto
**Author:** fun88337766
**Difficulty:** Easy

## TL;DR

Solve the quartic Diophantine equation `a^4 + b^4 + c^4 = d^4` with `c < 0` and `d > a > b > c`. This is a direct application of Elkies' 1988 counterexample to Euler's sum of powers conjecture.

## Description

The server presents a system with emoji-named variables:

```
Constraints:
  C < 0
  D > A > B > C

Equation:
  A**4 + B**4 + C**4 = D**4
```

We need to find integers satisfying all constraints.

## Analysis

Since `C < 0` but `C^4 = |C|^4` (even exponent), the equation is equivalent to finding positive integers `a, b, e, d` such that:

```
a^4 + b^4 + e^4 = d^4
```

with `C = -e`.

This is exactly **Euler's sum of powers conjecture** for degree 4 — Euler conjectured in 1769 that at least `n` fourth powers are needed to sum to a fourth power. This was disproven by **Noam Elkies** in 1988 who found:

```
2682440^4 + 15365639^4 + 18796760^4 = 20615673^4
```

## Solution

Assign the Elkies solution to the emoji variables:

| Variable | Value |
|----------|-------|
| A (largest after D) | 18796760 |
| B (middle) | 15365639 |
| C (negative) | -2682440 |
| D (largest) | 20615673 |

Verify constraints:
- `C = -2682440 < 0` &#10004;
- `D > A > B > C`: `20615673 > 18796760 > 15365639 > -2682440` &#10004;
- `18796760^4 + 15365639^4 + (-2682440)^4 = 20615673^4` &#10004;

## Solve Script

```python
from pwn import *

r = remote('dyn-01.midnightflag.fr', 12194)
r.recvuntil(b'Enter the value of')
r.sendline(b'18796760')
r.recvuntil(b'Enter the value of')
r.sendline(b'15365639')
r.recvuntil(b'Enter the value of')
r.sendline(b'-2682440')
r.recvuntil(b'Enter the value of')
r.sendline(b'20615673')
print(r.recvall().decode())
```

## Flag

```
MCTF{eb9b65f02ff7443a1b260247d90e36700b7a54a18446527dbdb8377d285f61a30c2564de1e42696e5826c92d95f41eae8f1f8769aeeecbf46bc98689c893615a}
```

## Key Lessons

- Recognizing classic number theory problems is essential for crypto CTF challenges
- Euler's sum of powers conjecture (disproven for degree 4) is a well-known result
- The negative constraint is a red herring since even powers make the sign irrelevant

## References

- Elkies, N. (1988). "On A^4 + B^4 + C^4 = D^4". Mathematics of Computation, 51(184), 825-835.
- [Wikipedia: Euler's sum of powers conjecture](https://en.wikipedia.org/wiki/Euler%27s_sum_of_powers_conjecture)
