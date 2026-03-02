# Ninth Symphony

| Field       | Value                              |
|-------------|------------------------------------|
| Platform    | caliphallabsRooted 2026            |
| Category    | reversing                          |
| Difficulty  | Medium                             |
| Points      | -                                  |
| Author      | -                                  |

## Description
> Have you ever wondered what a reverse shell sounds like? And an echo? No? Am I the only one? Well... now you're going to find out.
> The flag is located in /flag.txt.

## TL;DR
Custom bytecode VM interprets "melodies" (music notation strings) as instructions. Reverse-engineered the VM ISA (12 opcodes), the note-to-bytecode encoding system, and crafted a melody that reads `/flag.txt` and prints its contents.

## Initial Analysis

### Provided Files
- `ninth_symphony` -- ELF 64-bit LSB PIE executable, x86-64, dynamically linked, stripped
- `README.txt` -- Challenge description

### Reconnaissance
```
$ file ninth_symphony
ninth_symphony: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped

$ strings ninth_symphony | grep -i flag
/flag.txt

$ strings ninth_symphony | grep -i melod
Introduzca la melodía que desee reproducir:
```

The binary prompts for a "melody" string, parses it into bytecode, and executes it on a custom VM.

## Vulnerability Identified

### Type: Reversing / Custom VM

No exploit needed -- this is a pure reversing challenge. The goal is to understand the VM architecture and craft a program (encoded as a melody) that reads and prints `/flag.txt`.

## Solution Process

###  VM Architecture

The VM state struct (0x40c bytes):
- `state[0..7]`: 8 byte registers (r0-r7)
- `state[8..0x407]`: 1024 bytes memory
- `state[0x408..0x409]`: uint16 PC
- `state[0x40a]`: comparison flag
- `state[0x40b]`: extra register

###  Instruction Set

12 opcodes extracted from the switch table at `0x2010`:

| Opcode | Handler | Operation |
|--------|---------|-----------|
| 0      | HALT    | Return from VM |
| 1      | MOV     | `state[op1] = op2_value` |
| 2      | ADD     | `state[op1] += state[op2]` |
| 3      | XOR     | `state[op1] ^= state[op2]` |
| 4      | CMP     | `flag = (state[op2] == state[op1])` |
| 5      | JMP     | `PC = (op2 << 8) \| op1` |
| 6      | JNZ     | Jump if flag != 0 |
| 7      | JZ      | Jump if flag == 0 |
| 8      | LOAD    | `state[op1] = mem[state[op2]]` |
| 9      | STFLAG  | `state[0x40b] = state[op1]` |
| 10     | STORE   | `mem[state[op2]] = state[op1]` |
| 11     | SYSCALL | mode=state[op1]: 1=fopen, 2=putc |

**Critical finding**: Opcodes 2 and 3 are ADD and XOR respectively (not the other way around). Case 2 uses `add` x86 instruction, Case 3 uses `xor`.

###  Melody Encoding

Each instruction is 9 characters:

```
[0] Note letter (A-G) — opcode
[1] '#' for sharp, else any char
[2] Ignored padding character
[3] Note letter (A-G) — operand 1
[4] '#' for sharp
[5] Octave '1'-'9' or 'A'-'C'
[6] Note letter (A-G) — operand 2
[7] '#' for sharp
[8] Octave '1'-'9' or 'A'-'C'
```

**Opcode encoding** (handler-based):
- C=0, C#=1, D=2, D#=3, E=4, E#=5, F=5, F#=6, G=7, G#=8, A=9, A#=10, B=11, B#=0

**Operand encoding** (note_base table at `0x2060`):
- A=0, B=2, C=3, D=5, E=7, F=8, G=10
- With sharp: +1
- With octave: +12*(octave-1)

###  Crafting the Melody

Program logic:
1. Store "/flag.txt\0" in VM memory
2. Call fopen (SYSCALL mode 1) -- reads file into memory, zeroing it first
3. Loop: LOAD byte from memory, CMP with 0, JNZ to HALT if null, putc, ADD counter, JMP back
4. HALT

###  Debugging

**Bug 1**: Initially had ADD=3, XOR=2 (swapped). The loop used XOR instead of ADD to increment the counter, causing it to oscillate between 0 and 1 -- printing only memory[0] and memory[1] alternately ("clcl" pattern, which turned out to be the first two bytes of the flag "clctf{...}").

**Bug 2**: Earlier version had the padding byte at position [8] instead of [2], causing the parser to misinterpret the instruction layout.

## Final Exploit

```bash
python3 solve.py --remote
```

## Flag
```
clctf{VM_M310Dy_s0uNds_g00O0D!!}
```

## Key Lessons
- Always verify opcode semantics by reading the actual x86 instructions (`add` vs `xor`), not by guessing from case numbers
- When a VM produces a repeating pattern, check if the counter/index is advancing correctly -- XOR with 1 creates a toggle (0->1->0->1) instead of an increment
- The "clcl" output was actually the first two bytes of the flag, which was a useful clue
- Byte [2] in the 9-byte instruction format is unused padding -- this is determined by the parser reading operand 1 from `[rax+2]` where `rax = input+1`
