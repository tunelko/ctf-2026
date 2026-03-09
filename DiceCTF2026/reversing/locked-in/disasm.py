#!/usr/bin/env python3
"""Disassembler for the locked_in VM bytecode.

File format: flat array of u64 values.
Opcodes 6 (PUSH), 24 (JZ), 25 (JNZ), 26 (CALL) take a following u64 operand.
All other opcodes are single u64.
"""
import struct, sys

OPCODES = {
    0: "FUTEX_WAIT_BS", 1: "FUTEX_WAKE", 2: "FUTEX_WAIT", 3: "FUTEX_WAKE_N",
    4: "THREAD", 5: "HALT_TRUE", 6: "PUSH", 7: "POP",
    8: "DUP", 9: "OVER", 10: "ROT", 11: "RROT",
    12: "NOP", 13: "INC", 14: "DEC", 15: "ZERO",
    16: "ADD", 17: "SUB", 18: "MUL", 19: "DIV",
    20: "AND", 21: "OR", 22: "XOR", 23: "NOT",
    24: "JZ", 25: "JNZ", 26: "CALL", 27: "HALT_FALSE",
    28: "GETCHAR", 29: "PUTCHAR", 30: "LOAD", 31: "STORE",
}

HAS_OPERAND = {6, 24, 25, 26}

def disasm(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    n_u64s = len(data) // 8
    vals = [struct.unpack('<q', data[i*8:i*8+8])[0] for i in range(n_u64s)]

    # First pass: parse into instructions, track u64_pos -> insn_idx mapping
    instructions = []
    pos_to_insn = {}
    i = 0
    insn_idx = 0
    while i < n_u64s:
        pos_to_insn[i] = insn_idx
        opcode = vals[i]
        if opcode in HAS_OPERAND:
            operand = vals[i + 1] if i + 1 < n_u64s else 0
            instructions.append((opcode, operand, i))
            i += 2
        else:
            instructions.append((opcode, None, i))
            i += 1
        insn_idx += 1

    print(f"; {len(instructions)} instructions from {n_u64s} u64 values")

    # Second pass: print
    for idx, (opcode, operand, pos) in enumerate(instructions):
        name = OPCODES.get(opcode, f"UNK_{opcode}")
        extra = ""
        if opcode == 6 and operand is not None:
            if 0x20 <= operand <= 0x7e:
                extra = f"  ; '{chr(operand)}'"
            else:
                extra = f"  ; 0x{operand & 0xffffffffffffffff:x}"
            print(f"{idx:5d} [u{pos:5d}]: {name:<16s} {operand:>8d}{extra}")
        elif opcode in (24, 25) and operand is not None:
            # JZ/JNZ: PC += operand (relative to current instruction)
            target = idx + operand
            print(f"{idx:5d} [u{pos:5d}]: {name:<16s} {operand:>8d}  ; -> insn {target}")
        elif opcode == 26 and operand is not None:
            # CALL: absolute instruction index (but operand is u64 position, need to convert)
            # Actually the VM stores converted instructions at [r13] with index=operand
            # The operand IS the instruction index after parsing
            print(f"{idx:5d} [u{pos:5d}]: {name:<16s} {operand:>8d}  ; sub_{operand}")
        elif opcode == 4:
            print(f"{idx:5d} [u{pos:5d}]: {name:<16s}           ; spawn thread")
        elif operand is not None:
            print(f"{idx:5d} [u{pos:5d}]: {name:<16s} {operand:>8d}")
        else:
            print(f"{idx:5d} [u{pos:5d}]: {name:<16s}")

if __name__ == "__main__":
    disasm(sys.argv[1] if len(sys.argv) > 1 else "flag_verifier.bin")
