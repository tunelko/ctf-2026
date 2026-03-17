# 67 — Rev

**CTF:** Midnight Flag CTF 2026
**Category:** Reverse Engineering
**Flag:** `MCTF{R1ck_R0ll3d_1s_N0t_a_Pr0blem_1s_iT?}`

## TL;DR

Custom VM (xorshift hash + multiply) checks 861-byte input 3 bytes at a time across 287 groups. Sequential brute-force (each group depends on previous state) reveals the full lyrics of "Never Gonna Give You Up" with the flag appended.

## Analysis

**Binary:** ELF 64-bit, x86-64, PIE, stripped. Only imports: `strlen`, `puts`.

### Input validation
- `strlen(argv[1])` must be divisible by 3 (checked via multiplication trick with `0xaaaaaaaaaaaaaaab`)
- Input passed to VM function at `0x1200`

### VM Architecture
- **Registers:** `ebx` (accumulator, init `0xdeadbeef`), `ecx` (hash state), `ebp` (saved input XOR)
- **Bytecode:** at `.data` offset `0x4020`, each byte XOR'd with `0x7a` for opcode
- **6 opcodes** (after XOR `0x7a`):

| Opcode | Raw byte | Action |
|--------|----------|--------|
| `0x10` | `0x6a` | LOAD: `ecx = (input[i*3]<<16 \| input[i*3+1]<<8 \| input[i*3+2]) ^ ebx; ebp = ecx` |
| `0x11` | `0x6b` | `ecx ^= (ecx << 13)` |
| `0x12` | `0x68` | `ecx ^= (ecx >> 17)` |
| `0x13` | `0x69` | `ecx ^= (ecx << 5)` |
| `0x14` | `0x6e` | `ecx *= 0x2545f491` |
| `0x15` | `0x6f` | `ebx = ecx ^ ebp` |
| `0x20` | `0x5a` | COMPARE: read 4 data bytes, check `ebx == value` |
| — | `0x85` | HALT (success) |

### Bytecode structure
- 287 groups, each: `LOAD` + 1000× `(SHL13, SHR17, SHL5, IMUL)` + `XOREBP` + `COMPARE`
- Groups are chained: `ebx` output of group N becomes input to group N+1
- Total bytecode: ~1.15M bytes, total input: 287 × 3 = 861 bytes

### Hash function
The hash per group is essentially [xorshift32](https://en.wikipedia.org/wiki/Xorshift) with parameters (13, 17, 5) followed by multiplication by `0x2545f491`, iterated 1000 times. This is a one-way function — no analytical inverse exists.

## Solution

Since each group processes only 3 bytes and the state is chained, brute-force 3 bytes at a time (~16M candidates per group, with ~95^3 ≈ 857K for printable ASCII). Written in C with `-O3` for speed.

Each group takes ~1.5s in the printable range. Total: ~7 minutes for all 287 groups.

```c
// Core hash function
uint32_t hash_group(uint8_t b0, uint8_t b1, uint8_t b2, uint32_t ebx_in) {
    uint32_t ecx = ((uint32_t)b0 << 16) | ((uint32_t)b1 << 8) | b2;
    ecx ^= ebx_in;
    uint32_t ebp = ecx;
    for (int i = 0; i < 1000; i++) {
        ecx ^= (ecx << 13);
        ecx ^= (ecx >> 17);
        ecx ^= (ecx << 5);
        ecx *= 0x2545f491U;
    }
    return ecx ^ ebp;
}
```

Output: Full "Never Gonna Give You Up" lyrics + `Good Job, the flag is : MCTF{R1ck_R0ll3d_1s_N0t_a_Pr0blem_1s_iT?}`

## Key Lessons
- Custom VMs with small input blocks per check can be brute-forced sequentially
- xorshift+multiply hash is not reversible but 3-byte blocks are tractable (~857K printable candidates)
- Rickroll challenges hide the flag at the end of large known-plaintext payloads
