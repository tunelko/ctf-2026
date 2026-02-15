# Chip8 Emulator - Writeup

**Category:** Reversing
**Points:** 50 (beginner)
**Flag:** `0xfunCTF2025{N0w_y0u_h4v3_clear_1dea_H0w_3mulators_WoRK}`

---

## Description

> Ever wondered how emulators tick under the hood? I built one — the simplest of all, a CHIP-8 emulator. Alongside it, I've dropped 100+ games and programs for you to play… or are they really only for playing?
>
> Somewhere deep in this virtual silicon, a flaw hides. Uncover it, and in just quad cycles, the flag is yours. Miss it, and you'll be stuck endlessly.

An x86-64 ELF binary (`chip8Emulator`) is provided that implements a CHIP-8 emulator, along with ~100 classic game and demo ROMs.

## Analysis

### 1. Reconnaissance

```bash
$ file chip8Emulator
ELF 64-bit LSB pie executable, x86-64, not stripped

$ strings chip8Emulator | grep -i "flag\|flaw\|key"
Cooked CTF Presents : Chip8 Emulator :3
emu_key
keyaSEr
```

The binary is not stripped, which makes function analysis easier.

### 2. Suspicious Functions

When listing the `Cpu` class functions with radare2, we find functions that **do not belong to a standard CHIP-8 emulator**:

- `Cpu::cache()` -- 2732 bytes, the largest function
- `Cpu::superChipRendrer()` -- 1170 bytes, contains AES decryption logic
- `Cpu::base64Decode()` -- base64 decoder using OpenSSL BIO
- `Cpu::chat_toStr()` -- simple copy constructor

### 3. The "flaw": opcode FxFF

Analyzing `Cpu::decode_F_instruction()`, we find that when the low byte of the opcode is `0xFF`:

```
cmp eax, 0xff
je 0xe84c        ; -> calls Cpu::superChipRendrer()
```

In the CHIP-8 standard, the valid `Fxkk` opcodes are:
- `Fx07` -- LD Vx, DT
- `Fx0A` -- LD Vx, K
- `Fx15` -- LD DT, Vx
- `Fx18` -- LD ST, Vx
- `Fx1E` -- ADD I, Vx
- `Fx29` -- LD F, Vx
- `Fx33` -- LD B, Vx
- `Fx55` -- LD [I], Vx
- `Fx65` -- LD Vx, [I]

**`FxFF` does not exist** -- it is the emulator's intentional "flaw".

### 4. superChipRendrer Flow

When the opcode `FxFF` is executed, the `superChipRendrer()` function:

1. Takes the base64 data from a global variable `_3nc__2` (statically initialized):
   ```
   SMr85LT/QH8WBgB7FAHDJ+RDYEOzmc+8Hq+2HKyaEbwR0DN9...
   ```

2. Derives an AES-256 key from `emu_key` (generated in `Emulator::init` using the loaded ROM)

3. Decodes the base64 -> extracts the first 16 bytes as **IV** and the rest as **ciphertext**

4. Decrypts with **AES-256-CBC** using OpenSSL (`EVP_DecryptInit_ex`, `EVP_DecryptUpdate`, `EVP_DecryptFinal_ex`)

5. XORs each byte of the hardcoded string `0x5e525e044d4b464c` with `0x2a`, resulting in `flag.txt`

6. Writes the decrypted text to `flag.txt`

### 5. "Quad cycles"

The hint "in just quad cycles" = **4 CHIP-8 instructions**. We only need an 8-byte ROM (4 instructions of 2 bytes each), where the last one is `F0FF`.

## Solution

```bash
python3 solve.py
# [+] ROM created: /tmp/flaw.ch8 (8 bytes)
# [+] Opcodes: 600061006200f0ff
# [+] Flag: 0xfunCTF2025{N0w_y0u_h4v3_clear_1dea_H0w_3mulators_WoRK}
```

The created ROM:
```
0x200: 6000    ; LD V0, 0x00
0x202: 6100    ; LD V1, 0x00
0x204: 6200    ; LD V2, 0x00
0x206: F0FF    ; Hidden opcode -> decrypts and writes the flag
```

The emulator needs a virtual display and dummy audio:
```bash
xvfb-run -a env SDL_AUDIODRIVER=dummy ./chip8Emulator -r flaw.ch8 -l 0
cat flag.txt
```

## Flag

```
0xfunCTF2025{N0w_y0u_h4v3_clear_1dea_H0w_3mulators_WoRK}
```

## Notes

- The AES key is deterministically derived from the loaded ROM content through complex arithmetic operations in `Emulator::init`, using an alphanumeric charset
- `Cpu::cache()` copies the key between various bytearrays in BSS on each fetch cycle, but the main obfuscation block never executes (the control variable always equals 0)
- The ~100 included ROMs are legitimate CHIP-8 games; several contain `FF` bytes but as sprite data, not as executed opcodes
- The output filename (`flag.txt`) is obfuscated through XOR 0x2a on hardcoded bytes

## Files

- `the_Chip8_Emulator/chip8Emulator` -- Emulator binary
- `solve.py` -- Solution script (creates the ROM, runs the emulator, reads the flag)
