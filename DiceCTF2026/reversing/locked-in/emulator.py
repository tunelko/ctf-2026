#!/usr/bin/env python3
"""Emulator for the locked_in VM bytecode."""
import struct, sys, threading

HAS_OPERAND = {6, 24, 25, 26}

def load_program(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    n = len(data) // 8
    vals = [struct.unpack('<q', data[i*8:i*8+8])[0] for i in range(n)]

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
    return instructions

class VM:
    def __init__(self, instructions, memory_size=65536):
        self.insns = instructions
        self.memory = [0] * memory_size
        self.lock = threading.Lock()
        self.cond = threading.Condition(self.lock)
        self.input_buf = b""
        self.input_pos = 0
        self.trace = []
        self.max_trace = 50000

    def set_input(self, data):
        self.input_buf = data
        self.input_pos = 0

    def run(self, stack, pc, depth=0, trace=True):
        while 0 <= pc < len(self.insns):
            op, operand = self.insns[pc]

            if trace and len(self.trace) < self.max_trace:
                self.trace.append((depth, pc, op, operand, list(stack[-5:])))

            if op == 5:  # HALT_TRUE
                return True
            elif op == 27:  # HALT_FALSE
                return False
            elif op == 6:  # PUSH
                stack.append(operand)
            elif op == 7:  # POP
                stack.pop()
            elif op == 8:  # DUP
                stack.append(stack[-1])
            elif op == 9:  # OVER/DUP2
                a, b = stack[-2], stack[-1]
                stack.extend([a, b])
            elif op == 10:  # TUCK: [.., A, B, C] -> [.., A, C, B, C]
                top = stack[-1]
                stack.insert(-1, top)  # insert copy of top before second-from-top
            elif op == 11:  # UNTUCK: reverse of TUCK
                # [.., A, B, C] -> [.., B, A, C] with stack growing?
                # Let me implement based on assembly behavior
                # For safety, use similar logic as ROT but reversed
                if len(stack) >= 2:
                    second = stack[-2]
                    stack.insert(-1, second)  # dup second before top
                    del stack[-3]  # remove original second
                # This might be wrong, will check during execution
            elif op == 12:  # NOP
                pass
            elif op == 13:  # INC
                stack.append(stack.pop() + 1)
            elif op == 14:  # DEC
                x = stack.pop()
                stack.append(x - 1)
            elif op == 15:  # ZERO (pop, push 0)
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
                stack.append(a // b if b != 0 else 0)
            elif op == 20:  # AND
                b, a = stack.pop(), stack.pop()
                stack.append(a & b)
            elif op == 21:  # OR
                b, a = stack.pop(), stack.pop()
                stack.append(a | b)
            elif op == 22:  # XOR
                b, a = stack.pop(), stack.pop()
                stack.append(a ^ b)
            elif op == 23:  # NOT
                stack.append(~stack.pop())
            elif op == 24:  # JZ
                val = stack.pop()
                if val == 0:
                    pc += operand
                    continue
            elif op == 25:  # JNZ
                val = stack.pop()
                if val != 0:
                    pc += operand
                    continue
            elif op == 26:  # CALL
                ret = self.run(stack, operand, depth+1, trace)
                if ret:  # HALT_TRUE propagates up
                    return True
            elif op == 28:  # GETCHAR
                if self.input_pos < len(self.input_buf):
                    ch = self.input_buf[self.input_pos]
                    self.input_pos += 1
                    stack.append(ch)
                else:
                    stack.append(-1)  # EOF
            elif op == 29:  # PUTCHAR
                ch = stack.pop()
                sys.stdout.write(chr(ch & 0xff))
                sys.stdout.flush()
            elif op == 30:  # LOAD
                addr = stack.pop()
                stack.append(self.memory[addr])
            elif op == 31:  # STORE
                addr = stack.pop()
                val = stack.pop()
                self.memory[addr] = val
            elif op in (0, 1, 2, 3):  # FUTEX ops - treat as NOPs for single-thread
                if op == 0:  # FUTEX_WAIT_BS
                    addr = stack.pop()
                    stack.append(0)  # success
                elif op == 1:  # FUTEX_WAKE
                    addr = stack.pop()
                    stack.append(0)  # success
                elif op == 2:  # FUTEX_WAIT
                    count = stack.pop()
                    addr = stack.pop()
                    stack.append(0)
                elif op == 3:  # FUTEX_WAKE_N
                    count = stack.pop()
                    addr = stack.pop()
                    stack.append(0)
            elif op == 4:  # THREAD - skip for now
                pass
            else:
                print(f"Unknown opcode {op} at PC {pc}")
                return False

            pc += 1

        return False

def main():
    insns = load_program("flag_verifier.bin")
    vm = VM(insns)

    test_input = b"dice{test_flag_here}\n"
    if len(sys.argv) > 1:
        test_input = sys.argv[1].encode() + b"\n"

    vm.set_input(test_input)

    result = vm.run([], 0, trace=True)

    print(f"\n\n=== Result: {'ACCEPTED' if result else 'REJECTED'} ===")
    print(f"=== Trace ({len(vm.trace)} steps) ===")

    # Print first 200 trace entries
    for depth, pc, op, operand, stk in vm.trace[:200]:
        indent = "  " * min(depth, 4)
        from disasm import OPCODES
        name = OPCODES.get(op, f"UNK_{op}")
        stk_str = str(stk[-5:]) if stk else "[]"
        print(f"{indent}{pc:5d}: {name:<16s} {operand:>6d}  stk={stk_str}")

if __name__ == "__main__":
    main()
