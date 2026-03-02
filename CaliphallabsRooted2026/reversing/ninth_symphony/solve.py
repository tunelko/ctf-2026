#!/usr/bin/env python3
"""
Challenge: Ninth Symphony
Category:  reversing
Platform:  caliphallabsRooted2026

Music notation VM - craft a melody that reads /flag.txt and prints it.

Input format per instruction (9 chars):
  [0] Note letter (A-G) for opcode   - uses specific handlers
  [1] '#' for sharp, else anything
  [2] ignored/padding char
  [3] Note letter (A-G) for operand 1 - uses note_base table
  [4] '#' for sharp, else anything
  [5] Octave '1'-'9' or 'A'-'C'
  [6] Note letter (A-G) for operand 2 - uses note_base table
  [7] '#' for sharp, else anything
  [8] Octave '1'-'9' or 'A'-'C'

Opcode encoding (first byte, no octave):
  C=0, C#=1, D=2, D#=3, E=4, F=5(+sharp=6), G=7(+sharp=8), A=9(+sharp=10), B=11, B#=0(alt)

Operand encoding (second/third bytes, with octave):
  note_base: A=0, B=2, C=3, D=5, E=7, F=8, G=10
  value = note_base[letter] + is_sharp + 12*(octave-1)
"""
import sys

# === OPCODE ENCODING (first byte) ===
# Handler-based: each note letter has a specific handler
OPCODE_MAP = {
    0: ('C', False), 1: ('C', True), 2: ('D', False), 3: ('D', True),
    4: ('E', False), 5: ('F', False), 6: ('F', True),
    7: ('G', False), 8: ('G', True), 9: ('A', False),
    10: ('A', True), 11: ('B', False),
    # B#=0 is alternative for 0, but C works
}

# === OPERAND ENCODING (second/third bytes) ===
# Uses note_base table: A=0, B=2, C=3, D=5, E=7, F=8, G=10
NOTE_BASE = {'A': 0, 'B': 2, 'C': 3, 'D': 5, 'E': 7, 'F': 8, 'G': 10}
# With sharp: +1, with octave: +12*(oct-1)
# Reachable values per note+sharp:
# A=0, A#=1, B=2, B#=3, C=3, C#=4, D=5, D#=6, E=7, E#=8, F=8, F#=9, G=10, G#=11
# Per octave adds 12

def opcode_str(val):
    """Encode opcode value (0-11) as 2-char note."""
    note, sharp = OPCODE_MAP[val]
    return note + ('#' if sharp else '-')

def operand_str(val):
    """Encode operand value (0-143) as 3-char note+octave."""
    # Find note_base + sharp + octave that gives val
    # val = note_base[letter] + sharp + 12*(octave-1)
    # octave range: 1-9 (standard) or A=10, B=11, C=12

    # Try all combinations
    for octave_num in range(1, 13):
        base_from_octave = 12 * (octave_num - 1)
        remainder = val - base_from_octave
        if remainder < 0 or remainder > 11:
            continue

        # Find a note+sharp combo for this remainder
        for letter, nbase in NOTE_BASE.items():
            if nbase == remainder:
                # No sharp
                if octave_num <= 9:
                    return letter + '-' + str(octave_num)
                else:
                    return letter + '-' + chr(ord('A') + octave_num - 10)
            elif nbase + 1 == remainder:
                # With sharp
                if octave_num <= 9:
                    return letter + '#' + str(octave_num)
                else:
                    return letter + '#' + chr(ord('A') + octave_num - 10)

    raise ValueError(f"Cannot encode operand value {val}")


def encode(opcode, op1, op2):
    """Encode one VM instruction as 9-char melody fragment.
    Format: [0-1] opcode (note+sharp), [2] padding (ignored),
    [3-5] op1 (note+sharp+octave), [6-8] op2 (note+sharp+octave)."""
    return opcode_str(opcode) + '-' + operand_str(op1) + operand_str(op2)


# VM opcodes (case 2=ADD via x86 add, case 3=XOR via x86 xor)
HALT = 0; MOV = 1; ADD = 2; XOR = 3; CMP = 4; JMP = 5; JNZ = 6; JZ = 7
LOAD = 8; STFLAG = 9; STORE = 10; SYSCALL = 11

instructions = []
pc = 0

def emit(opcode, op1, op2, comment=""):
    global pc
    instructions.append((opcode, op1, op2, comment))
    pc += 3

# === Program: read /flag.txt and print contents ===

filename = "/flag.txt\x00"
for i, ch in enumerate(filename):
    emit(MOV, 0, ord(ch), f"r0 = {ord(ch)} ('{ch}')")
    emit(MOV, 1, i,        f"r1 = {i}")
    emit(STORE, 0, 1,      f"mem[r1] = r0")

# fopen
emit(MOV, 0, 1, "r0 = 1 (fopen)")
emit(MOV, 1, 0, "r1 = 0 (filename ptr)")
emit(SYSCALL, 0, 1, "fopen(mem@r1)")

# Print loop setup
emit(MOV, 1, 0, "r1 = 0 (counter)")
emit(MOV, 4, 0, "r4 = 0 (null)")
emit(MOV, 5, 1, "r5 = 1 (increment)")

# Loop start
loop_start = pc
emit(LOAD, 2, 1,  "r2 = mem[r1]")
emit(CMP, 4, 2,   "flag = (r2 == r4)?")
end_jmp_idx = len(instructions)
emit(JNZ, 0, 0,   "JNZ end (placeholder)")

# Print char
emit(MOV, 0, 2,   "r0 = 2 (putc)")
emit(SYSCALL, 0, 2, "putc(r2)")

# Increment and loop
emit(ADD, 1, 5,    "r1 += r5")
emit(JMP, loop_start & 0xFF, (loop_start >> 8) & 0xFF, f"JMP {loop_start}")

# End
end_pc = pc
emit(HALT, 0, 0, "HALT")

# Patch JNZ target
instructions[end_jmp_idx] = (JNZ, end_pc & 0xFF, (end_pc >> 8) & 0xFF, f"JNZ {end_pc}")

# Generate melody
melody = ""
for opcode, op1, op2, comment in instructions:
    fragment = encode(opcode, op1, op2)
    melody += fragment

print(f"Melody ({len(melody)} chars, {len(instructions)} instructions):")
print(melody)
print()

print("Bytecode:")
for i, (opcode, op1, op2, comment) in enumerate(instructions):
    print(f"  PC={i*3:3d}: [{opcode:2d}, {op1:3d}, {op2:3d}]  {comment}")

# Verify encoding by decoding
print("\nVerifying decode...")
def decode_opcode(s):
    """Decode 2-char opcode."""
    rev = {v: k for k, v in OPCODE_MAP.items()}
    note = s[0]
    sharp = (len(s) > 1 and s[1] == '#')
    return rev.get((note, sharp), -1)

def decode_operand(s):
    """Decode 3-char operand."""
    note = s[0]
    sharp = (s[1] == '#')
    oc = s[2]
    base = NOTE_BASE.get(note, -1)
    if base < 0:
        return -1
    val = base + (1 if sharp else 0)
    if oc.isdigit():
        val += 12 * (int(oc) - 1)
    elif oc in 'ABC':
        val += 12 * (ord(oc) - ord('A') + 9)
    return val

ok = True
for idx, (opcode, op1, op2, comment) in enumerate(instructions):
    frag = melody[idx*9:(idx+1)*9]
    d_op = decode_opcode(frag[0:2])
    d_o1 = decode_operand(frag[3:6])
    d_o2 = decode_operand(frag[6:9])
    if d_op != opcode or d_o1 != op1 or d_o2 != op2:
        print(f"  MISMATCH at {idx}: expected [{opcode},{op1},{op2}] got [{d_op},{d_o1},{d_o2}] from '{frag}'")
        ok = False
if ok:
    print("  All instructions verified OK!")

if "--remote" in sys.argv:
    from pwn import *
    io = remote("challs.caliphallabs.com", 35631)
    io.recvuntil(b": ")
    io.sendline(melody.encode())
    data = io.recvall(timeout=5)
    print(f"\nOutput: {data.decode(errors='replace')}")
