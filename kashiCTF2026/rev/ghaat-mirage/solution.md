# Ghaat Mirage

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | KashiCTF 2026                  |
| Categoría   | rev                            |

## Descripcion
> The ghats of Kashi each glow, but only one is real. Find the true ghat, offer the correct mantra, and receive moksha.

## TL;DR
UPX-packed binary with decoy flag path (always prints fake). True path validates 32-byte input via polynomial hash (4 accumulators, multiplier 0x83). Cracked with meet-in-the-middle attack.

## Proceso

### Paso 1: Recon
Binary is UPX 5.0 packed. Any input produces decoy: `kashi{fr4ke_g4ng4_0ffering_lol}`. No input validation visible at surface level.

### Paso 2: Dump decompressed code
Used `sudo gdb` to catch `exit_group` syscall and dump the memfd:upx region (4096 bytes at 0x7ffff7ff9000).

### Paso 3: Reverse the validator
Disassembly revealed:
1. `strlen(input) == 0x20` — input must be exactly 32 bytes
2. Polynomial hash with 4 accumulators (`acc[pos%4] = acc[pos%4] * 0x83 + byte`)
3. Comparison against 4 constants:
   - `acc[0] = 0x00fd91b66d4b8b11`
   - `acc[1] = 0x00e661491544fdb8`
   - `acc[2] = 0x010fc69e6442ef55`
   - `acc[3] = 0x00f680346b31a222`
4. Accumulator 0 initialized to `input[0]`, others to 0

### Paso 4: Meet-in-the-middle crack
With known prefix `kashi{` and suffix `}`, each accumulator has 6-7 unknown bytes. MITM splits each into two halves, building a hash table for the left half and searching for matches from the right half. Uses modular inverse of `0x83^n` mod `2^64`.

Cracks all 4 accumulators in <1 second.

## Flag
```
kashi{Gh4t5_0f_K4sh1_Never_Di35}
```

## Key Lessons
- UPX 5.0 uses memfd_create → code decompressed in memory, not on disk. Dump via GDB at syscall catch
- Decoy flags are common in rev challenges — always verify by finding the actual validation logic
- Polynomial hashes with independent accumulators are vulnerable to meet-in-the-middle (exponential speedup)
- `acc[pos%4]` splits 32-byte input into 4 independent 8-byte problems → each crackable independently
