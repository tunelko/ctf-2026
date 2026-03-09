#!/usr/bin/env python3
"""Trace sub_1463 with W=1 to understand the full char relay pipeline."""
import struct

# Load disassembly
with open('flag_verifier.bin', 'rb') as f:
    data = f.read()
n = len(data) // 8
vals = [struct.unpack('<q', data[i*8:i*8+8])[0] for i in range(n)]

HAS_OPERAND = {6, 24, 25, 26}
instructions = []
i = 0
while i < n:
    op = vals[i]
    if op in HAS_OPERAND:
        operand = vals[i+1] if i+1 < n else 0
        instructions.append((op, operand))
        i += 2
    else:
        instructions.append((op, 0))
        i += 1

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

# Evaluate the "PUSH V; DUP; ZERO; FUTEX_WAKE; ROT; <ops>; MUL; RROT; <ops>; ADD; ADD"
# pattern that computes f(V, W)
def eval_fw_block(stack, W=1):
    """Given stack [..., V, V, W] after ROT, simulate until we get the final value."""
    pass

# Let me just trace sub_1463 manually using a stack VM with W=1
W = 1

def execute_sub1463():
    """Execute sub_1463 starting at instruction 1463 with W=1."""
    pc = 1463
    stack = []

    # Map of what we know
    operations = []  # List of (action, channel/value)

    while pc < len(instructions):
        op, operand = instructions[pc]
        name = OPCODES.get(op, f"UNK_{op}")

        if op == 6:  # PUSH
            stack.append(operand)
        elif op == 7:  # POP
            stack.pop()
        elif op == 8:  # DUP
            stack.append(stack[-1])
        elif op == 9:  # OVER
            a, b = stack[-2], stack[-1]
            stack.extend([a, b])
        elif op == 10:  # ROT (TUCK)
            top = stack[-1]
            stack.insert(-2, top)
        elif op == 11:  # RROT (SWAP)
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op == 13:  # INC
            stack[-1] += 1
        elif op == 14:  # DEC
            stack[-1] -= 1
        elif op == 15:  # ZERO
            stack.pop()
            stack.append(0)
        elif op == 16:  # ADD
            b, a = stack.pop(), stack.pop()
            stack.append(a + b)
        elif op == 17:  # SUB
            b, a = stack.pop(), stack.pop()
            stack.append(a - b)
        elif op == 18:  # MUL
            b, a = stack.pop(), stack.pop()
            stack.append(a * b)
        elif op == 19:  # DIV
            b, a = stack.pop(), stack.pop()
            stack.append(a // b if b else 0)
        elif op == 20:  # AND
            b, a = stack.pop(), stack.pop()
            stack.append(a & b)
        elif op == 21:  # OR
            b, a = stack.pop(), stack.pop()
            stack.append(a | b)
        elif op == 22:  # XOR
            b, a = stack.pop(), stack.pop()
            if isinstance(a, str) or isinstance(b, str):
                stack.append(f"({a} ^ {b})")
            else:
                stack.append(a ^ b)
        elif op == 23:  # NOT
            stack[-1] = ~stack[-1]
        elif op == 1:  # FUTEX_WAKE
            addr = stack.pop()
            stack.append(W)  # Return W
        elif op == 26:  # CALL
            target = operand
            if target == 4195:  # sub_4195 = receive from channel
                ch = stack.pop()
                print(f"  pc={pc}: RECEIVE from channel {ch} ('{chr(ch) if 32<=ch<127 else '?'}')")
                stack.append(f"data_from_{ch}")  # symbolic
                operations.append(('RECV', ch))
            elif target == 4232:  # sub_4232 = ack channel with data
                ch = stack.pop()
                data = stack.pop()
                print(f"  pc={pc}: ACK channel {ch} ('{chr(ch) if 32<=ch<127 else '?'}') with {data}")
                operations.append(('ACK', ch, data))
            elif target == 4098:  # sub_4098 = send with ack
                ch = stack.pop()
                data = stack[-1]  # peek, not pop
                stack.pop()
                print(f"  pc={pc}: SEND_ACK to channel {ch} ('{chr(ch) if 32<=ch<127 else '?'}') data={data}")
                stack.append(f"ack_from_{ch}")
                operations.append(('SEND_ACK', ch, data))
            else:
                print(f"  pc={pc}: CALL sub_{target} (unknown)")
                break
        elif op == 24:  # JZ
            val = stack.pop()
            if isinstance(val, int) and val == 0:
                pc += operand
                continue
            elif isinstance(val, str):
                print(f"  pc={pc}: JZ with symbolic value {val} — can't evaluate")
                break
        elif op == 25:  # JNZ
            val = stack.pop()
            if isinstance(val, int) and val != 0:
                pc += operand
                continue
            elif isinstance(val, str):
                print(f"  pc={pc}: JNZ with symbolic value {val} — can't evaluate")
                break
        elif op == 27:  # HALT_FALSE
            print(f"  pc={pc}: HALT_FALSE (return)")
            break
        elif op == 4:  # THREAD
            print(f"  pc={pc}: THREAD (end of this thread's init)")
            break
        else:
            print(f"  pc={pc}: {name} (unhandled)")
            if op not in (0, 2, 3, 12):
                break

        pc += 1

    return operations

print("=== Sub_1463 trace with W=1 ===")
ops = execute_sub1463()
print(f"\nTotal operations: {len(ops)}")
