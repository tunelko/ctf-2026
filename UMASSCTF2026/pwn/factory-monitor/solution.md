# Factory Monitor — UMassCTF 2026 (PWN, 491pts, 16 solves)

## TL;DR
PIE ASLR brute-force via fork()+exit code oracle en child process, seguido de stack overflow ROP en el proceso padre para obtener shell.

## Descripción
> I made a factory monitor to keep an eye on the machines, but it seems to be malfunctioning. Can you help me fix it?

Binary que simula un monitor de fábrica. Gestiona "máquinas" (procesos hijo fork'd) con pipes bidireccionales. Los hijos ejecutan un loop echo y el padre tiene un CLI interactivo.

## Análisis

```bash
checksec --file=factory-monitor
# RELRO: Full    Stack Canary: No    NX: Yes    PIE: Yes    ASLR: On
```

- **Sin canary** → stack overflow directo
- **PIE** → necesitamos leak de base address
- **fork()** → los hijos heredan el mismo address space (misma base PIE)
- Hint: "child processes inherit a lot from their parents"

### Primitivas

1. `send <id> <data>` — escribe datos al child via pipe
2. `recv <id> <len>` — lee respuesta del child (echo) a un buffer en stack del **padre**
3. `monitor <id>` — muestra estado del child (running/exited + exit code)
4. `create <name>` — crea nueva máquina en BSS array

### Vulnerabilidad 1: Child overflow (PIE leak)
El child lee del pipe a un buffer local sin bounds check. Overflow del return address del child.

**Oracle**: partial overwrite (2 bytes) del ret addr → si el child ejecuta `exit_group(127)`, `monitor` reporta "status 127". Si crashea → "signal 11".

El child ret addr original = `base + 0xb43d`. Overwrite a `base + 0xe333` (gadget `mov edi, 0x7f; call exit_group`). Solo byte 0 (0x33) es fijo. Byte 1 depende de `(base >> 12) & 0xF` → **16 candidatos**.

Brute-force byte por byte (bytes 1-4), cada vez verificando con exit code 127.

### Vulnerabilidad 2: Parent overflow (ROP → shell)
`recv` lee datos del child echo a un buffer de 304 bytes en el stack del padre **sin length check**. Al enviar un payload largo al child, el echo excede el buffer → overflow del return address del padre.

Con PIE base conocido, ROP chain:
```
POP_RDI_RBP (0xc028) → "/bin/sh" addr
POP_RSI_RBP (0x15b26) → 0
POP_RAX_RDX_LEAVE (0x7c5b2) → 59 (SYS_execve), 0
SYSCALL_RET (0x38129)
```

Las strings "/bin/sh" y datos auxiliares se colocan como nombres de máquinas en BSS (via `create`).

## Exploit

```python
# Fase 1: PIE leak via child overflow + exit code oracle
# - Overwrite 2 bytes: [0x33, candidate_byte1]
# - Si monitor reporta "status 127" → byte correcto
# - Repetir para bytes 2, 3, 4
# → PIE base = ret_addr - 0xe333

# Fase 2: Setup en BSS
# create "/bin/sh"  → string en BSS para execve
# create pivot_data → SYSCALL_RET addr para leave gadget

# Fase 3: Parent overflow
# send payload largo al child → child echo → recv desborda stack padre
# ROP: execve("/bin/sh", NULL, NULL)
```

Script completo: `solve_final.py`

## Flag
```
UMASS{f0rk_f0rk_f0rk_PIE_l34k_4nd_r0p}
```
*(flag obtenida en remoto durante el CTF)*

## Key Lessons
- `fork()` preserva el address space → brute-force parcial del PIE base via exit code oracle
- Solo 16 candidatos para byte 1 (depende de `base & 0xF000`), luego 256 por byte subsiguiente
- Los nombres de máquinas almacenados en BSS sirven como storage controlado para strings de ROP
- El child echo sin bounds check crea un "return-to-oracle" + pipeline overflow al padre
