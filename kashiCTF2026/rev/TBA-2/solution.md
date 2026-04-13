# TBA-2 — kashiCTF 2026

| Field | Value |
|-------|-------|
| Category | Reversing |
| Points | 469 |
| Author | MarshmalloQi |
| Flag | `kashiCTF{had_to_create_an_entire_new_challenge_but_it_w4s_rev_50_have_fun}` |

## TL;DR

UPX 5.11 packed binary with anti-debug. Computes the real flag from `challenge_data.bin` via bytecode VM, then `memcmp` against user input. Break at `memcmp` in GDB (bypassing TracerPid check) to read the computed flag from memory.

## Description

> The announcement never aired. Only fragments survived.
> Some say the challenge is still To Be Announced.

Files: `prog` (UPX-packed ELF), `challenge_data.bin` (80KB, 1536 encrypted records).

## Analysis

### Unpacking

```
$ file prog
ELF 64-bit LSB pie executable, x86-64, statically linked, no section header
$ strings prog | grep UPX
$Id: UPX 5.11 Copyright (C) 1996-2026 the UPX Team.
```

System UPX 3.96 can't unpack UPX 5.11. Downloaded UPX 5.0.1:

```
$ /tmp/upx-5.0.1-amd64_linux/upx -d prog -o prog_unpacked
  18424 <- 11504   62.44%   linux/amd64   prog_unpacked
```

### Binary behavior

```
$ ./prog "anything"
=== TBA-2 :: FINAL BROADCAST ===
Only one signal is true.
kashiCTF{TBA2_false_broadcast_B}
```

Always outputs one of 3 hardcoded false flags (A, B, C) regardless of input. The output varies based on a hash of the input — but all are decoys.

### Reversing key points

1. **Anti-debug**: Reads `/proc/self/status` for `TracerPid:`, calls `strtol`, exits if non-zero. Also uses `clock_gettime` timing checks.
2. **Data loading**: Reads `challenge_data.bin` — header `TBA2DATA`, version=1, 1536 records of 52 bytes. Verifies FNV-1a hash of data.
3. **Bytecode VM**: Decrypts embedded bytecode at `0x31e0` using XOR+rotate cipher, interprets it via a switch-case VM (11 opcodes) to compute the real flag from the encrypted records.
4. **Verification**: `strlen(argv[1]) == 0x4A (74)` then `memcmp(argv[1], computed_flag, 0x4A)`. On match: prints `[broadcast] channel stabilized` + echoes the flag.

## Solution

Break at `memcmp` in GDB, bypass anti-debug by zeroing `r12` at the TracerPid check:

```bash
dummy='kashiCTF{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}'

gdb -q -batch \
  -ex "set args $dummy" \
  -ex "b *0x555555555144" \
  -ex "run" \
  -ex "set \$r12 = 0" \
  -ex "b *0x555555555da2" \
  -ex "c" \
  -ex "x/s \$rsi" \
  -ex "quit" \
  ./prog_unpacked
```

Output:
```
0x55555555b910: "kashiCTF{had_to_create_an_entire_new_challenge_but_it_w4s_rev_50_have_fun}"
```

Verify:
```
$ ./prog_unpacked 'kashiCTF{had_to_create_an_entire_new_challenge_but_it_w4s_rev_50_have_fun}'
=== TBA-2 :: FINAL BROADCAST ===
Only one signal is true.
[broadcast] channel stabilized
kashiCTF{had_to_create_an_entire_new_challenge_but_it_w4s_rev_50_have_fun}
```

## Key Lessons

- UPX version mismatch: always check the packer version and use a compatible unpacker
- Anti-debug bypass: patching TracerPid check at runtime with GDB is trivial
- When a binary computes the answer internally and compares, break at `memcmp`/`strcmp` to read it directly — no need to fully reverse the computation
