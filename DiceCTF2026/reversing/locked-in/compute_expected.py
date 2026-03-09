#!/usr/bin/env python3
"""Symbolically compute expected values as f(W) where W = FUTEX_WAKE return value."""

# Each block follows pattern:
# PUSH V; DUP; ZERO; FUTEX_WAKE; ROT
# <compute multiplier from W>; MUL (with V); RROT
# <compute second term from W>
# ADD; PUSH addr; STORE
#
# ROT = TUCK: [a,b,c] -> [a,c,b,c] (insert copy of top before [-2])
# RROT = SWAP: swap top 2

# I'll manually parse each block from the disassembly

def simulate_block(V, ops_after_rot):
    """
    After PUSH V; DUP; ZERO; FUTEX_WAKE; ROT we have stack [W, V, W]
    Then ops_after_rot are applied, ending with ADD (which combines the two parts).
    Returns a function f(W) -> expected value.
    """
    pass

# Let me just directly trace each block for W=0 and W=1

def trace_block(V, middle_ops, rrot_ops, final_add):
    """Trace a block with symbolic W."""
    results = {}
    for W in range(2):
        # After PUSH V; DUP; ZERO; FUTEX_WAKE; ROT
        # ROT on [V, W] (2 elements): insert W at -2 -> [W, V, W]
        stack = [W, V, W]

        # Execute middle_ops on stack (these compute f(W) and multiply with V)
        for op in middle_ops:
            if op[0] == 'PUSH':
                stack.append(op[1])
            elif op[0] == 'ADD':
                b, a = stack.pop(), stack.pop()
                stack.append(a + b)
            elif op[0] == 'MUL':
                b, a = stack.pop(), stack.pop()
                stack.append(a * b)
            elif op[0] == 'DUP':
                stack.append(stack[-1])
            elif op[0] == 'RROT':  # SWAP
                stack[-1], stack[-2] = stack[-2], stack[-1]
            elif op[0] == 'ROT':  # TUCK
                top = stack[-1]
                stack.insert(-2, top)
            elif op[0] == 'ZERO':
                stack.pop()
                stack.append(0)

        results[W] = stack[-1]  # final value after last ADD
    return results

# Parse each block from disassembly
# Block format: after ROT we have [W, V, W], then operations until STORE

blocks = []

# mem[137]: V=2147483647
# After ROT [W, V, W]:
# PUSH 1; ADD -> [W, V, W+1]
# MUL -> [W, V*(W+1)]
# RROT -> [V*(W+1), W]
# PUSH 1; ROT -> [V*(W+1), 1, W, 1]
# MUL -> [V*(W+1), 1, W]
# MUL -> [V*(W+1), W]
# PUSH 0; ADD -> [V*(W+1), W]
# ADD -> V*(W+1)+W
blocks.append((137, 2147483647, [
    ('PUSH', 1), ('ADD',), ('MUL',),
    ('RROT',),
    ('PUSH', 1), ('ROT',), ('MUL',), ('MUL',),
    ('PUSH', 0), ('ADD',),
    ('ADD',)
]))

# mem[138]: V=306790510
# DUP; ADD -> 2W; DUP; ADD -> 4W; PUSH 3; ADD -> 4W+3; MUL -> V*(4W+3)
# RROT; PUSH 1; ROT; MUL; MUL -> W*1*1=W (wait, need to trace carefully)
# Actually: RROT -> [V*(4W+3), W]; PUSH 1; ROT -> [V*(4W+3), 1, W, 1]; MUL -> [V*(4W+3), 1, W]; MUL -> [V*(4W+3), W]
# PUSH 0; ADD; ADD -> V*(4W+3)+W
blocks.append((138, 306790510, [
    ('DUP',), ('ADD',), ('DUP',), ('ADD',), ('PUSH', 3), ('ADD',), ('MUL',),
    ('RROT',),
    ('PUSH', 1), ('ROT',), ('MUL',), ('MUL',),
    ('PUSH', 0), ('ADD',),
    ('ADD',)
]))

# mem[139]: V=733718038
# PUSH 3; ADD -> W+3; MUL -> V*(W+3)
# RROT; PUSH 1; ROT; MUL; MUL
# PUSH 0; ADD; ADD
blocks.append((139, 733718038, [
    ('PUSH', 3), ('ADD',), ('MUL',),
    ('RROT',),
    ('PUSH', 1), ('ROT',), ('MUL',), ('MUL',),
    ('PUSH', 0), ('ADD',),
    ('ADD',)
]))

# mem[140]: V=314417355
# DUP; ADD -> 2W; DUP; ADD -> 4W; PUSH 5; ADD -> 4W+5; MUL -> V*(4W+5)
# RROT; PUSH 1; ROT; MUL; MUL
# PUSH 1; ADD; ADD
blocks.append((140, 314417355, [
    ('DUP',), ('ADD',), ('DUP',), ('ADD',), ('PUSH', 5), ('ADD',), ('MUL',),
    ('RROT',),
    ('PUSH', 1), ('ROT',), ('MUL',), ('MUL',),
    ('PUSH', 1), ('ADD',),
    ('ADD',)
]))

# mem[141]: V=353735953
# DUP; ADD -> 2W; DUP; ADD -> 4W; PUSH 4; ADD -> 4W+4; MUL -> V*(4W+4)
# RROT; PUSH 1; ROT; MUL; MUL
# PUSH 0; ADD; ADD
blocks.append((141, 353735953, [
    ('DUP',), ('ADD',), ('DUP',), ('ADD',), ('PUSH', 4), ('ADD',), ('MUL',),
    ('RROT',),
    ('PUSH', 1), ('ROT',), ('MUL',), ('MUL',),
    ('PUSH', 0), ('ADD',),
    ('ADD',)
]))

# mem[142]: V=707436696
# PUSH 3; ADD -> W+3; MUL -> V*(W+3)
# RROT; PUSH 1; ROT; MUL; MUL
# PUSH 0; ADD; ADD
blocks.append((142, 707436696, [
    ('PUSH', 3), ('ADD',), ('MUL',),
    ('RROT',),
    ('PUSH', 1), ('ROT',), ('MUL',), ('MUL',),
    ('PUSH', 0), ('ADD',),
    ('ADD',)
]))

# mem[143]: V=1467318167
# PUSH 1; ADD -> W+1; MUL -> V*(W+1)
# RROT; PUSH 1; ROT; MUL; MUL
# PUSH 0; ADD; ADD
blocks.append((143, 1467318167, [
    ('PUSH', 1), ('ADD',), ('MUL',),
    ('RROT',),
    ('PUSH', 1), ('ROT',), ('MUL',), ('MUL',),
    ('PUSH', 0), ('ADD',),
    ('ADD',)
]))

# mem[144]: V=894796515
# PUSH 2; ADD -> W+2; MUL -> V*(W+2)
# RROT; ZERO; ADD -> [V*(W+2), 0]
# PUSH 144; STORE
# Wait, this one is different! Let me re-read...
# 1002: FUTEX_WAKE -> [V, W]
# 1003: ROT -> [W, V, W]
# 1004: PUSH 2; ADD -> [W, V, W+2]
# 1006: MUL -> [W, V*(W+2)]
# 1007: RROT -> [V*(W+2), W]
# 1008: ZERO -> [V*(W+2), 0]
# 1009: ADD -> [V*(W+2)]
# Then PUSH 144; STORE
blocks.append((144, 894796515, [
    ('PUSH', 2), ('ADD',), ('MUL',),
    ('RROT',),
    ('ZERO',),
    ('ADD',),
]))

# mem[145]: V=298255307
# DUP; ADD -> 2W; DUP; ADD -> 4W; PUSH 5; ADD -> 4W+5; MUL -> V*(4W+5)
# RROT; PUSH 2; ROT; MUL; MUL
# PUSH 2; ADD; ADD
blocks.append((145, 298255307, [
    ('DUP',), ('ADD',), ('DUP',), ('ADD',), ('PUSH', 5), ('ADD',), ('MUL',),
    ('RROT',),
    ('PUSH', 2), ('ROT',), ('MUL',), ('MUL',),
    ('PUSH', 2), ('ADD',),
    ('ADD',)
]))

# mem[146]: V=876647801
# PUSH 3; ADD -> W+3; MUL -> V*(W+3)
# RROT; PUSH 1; ROT; MUL; MUL
# PUSH 0; ADD; ADD
blocks.append((146, 876647801, [
    ('PUSH', 3), ('ADD',), ('MUL',),
    ('RROT',),
    ('PUSH', 1), ('ROT',), ('MUL',), ('MUL',),
    ('PUSH', 0), ('ADD',),
    ('ADD',)
]))

# mem[147]: V=836993713
# PUSH 2; ADD -> W+2; MUL -> V*(W+2)
# RROT; ZERO; ADD
blocks.append((147, 836993713, [
    ('PUSH', 2), ('ADD',), ('MUL',),
    ('RROT',),
    ('ZERO',),
    ('ADD',),
]))

# mem[148]: V=350907053
# DUP; ADD -> 2W; DUP; ADD -> 4W; PUSH 6; ADD -> 4W+6; MUL -> V*(4W+6)
# RROT; PUSH 3; ROT; MUL; MUL
# PUSH 0; ADD; ADD
blocks.append((148, 350907053, [
    ('DUP',), ('ADD',), ('DUP',), ('ADD',), ('PUSH', 6), ('ADD',), ('MUL',),
    ('RROT',),
    ('PUSH', 3), ('ROT',), ('MUL',), ('MUL',),
    ('PUSH', 0), ('ADD',),
    ('ADD',)
]))

# mem[149]: V=501288686 (note: 501288686 not 501288688)
# DUP; ADD -> 2W; DUP; ADD -> 4W; PUSH 1; ADD -> 4W+1; MUL -> V*(4W+1)
# RROT; PUSH 1; ROT; MUL; MUL
# PUSH 2; ADD; ADD
blocks.append((149, 501288686, [
    ('DUP',), ('ADD',), ('DUP',), ('ADD',), ('PUSH', 1), ('ADD',), ('MUL',),
    ('RROT',),
    ('PUSH', 1), ('ROT',), ('MUL',), ('MUL',),
    ('PUSH', 2), ('ADD',),
    ('ADD',)
]))

# mem[150]: V=693463725
# PUSH 3; ADD -> W+3; MUL -> V*(W+3)
# RROT; PUSH 1; ROT; MUL; MUL
# PUSH 0; ADD; ADD
blocks.append((150, 693463725, [
    ('PUSH', 3), ('ADD',), ('MUL',),
    ('RROT',),
    ('PUSH', 1), ('ROT',), ('MUL',), ('MUL',),
    ('PUSH', 0), ('ADD',),
    ('ADD',)
]))

# mem[151]: V=1140986114
# PUSH 1; ADD -> W+1; MUL -> V*(W+1)
# RROT; PUSH 1; ROT; MUL; MUL
# PUSH 0; ADD; ADD
blocks.append((151, 1140986114, [
    ('PUSH', 1), ('ADD',), ('MUL',),
    ('RROT',),
    ('PUSH', 1), ('ROT',), ('MUL',), ('MUL',),
    ('PUSH', 0), ('ADD',),
    ('ADD',)
]))

# mem[152]: V=613566756
# DUP; ADD -> 2W; DUP; ADD -> 4W; PUSH 3; ADD -> 4W+3; MUL -> V*(4W+3)
# RROT; PUSH 1; ROT; MUL; MUL
# PUSH 2; ADD; ADD
blocks.append((152, 613566756, [
    ('DUP',), ('ADD',), ('DUP',), ('ADD',), ('PUSH', 3), ('ADD',), ('MUL',),
    ('RROT',),
    ('PUSH', 1), ('ROT',), ('MUL',), ('MUL',),
    ('PUSH', 2), ('ADD',),
    ('ADD',)
]))

def execute(stack, ops):
    for op in ops:
        if op[0] == 'PUSH':
            stack.append(op[1])
        elif op[0] == 'ADD':
            b, a = stack.pop(), stack.pop()
            stack.append(a + b)
        elif op[0] == 'MUL':
            b, a = stack.pop(), stack.pop()
            stack.append(a * b)
        elif op[0] == 'DUP':
            stack.append(stack[-1])
        elif op[0] == 'RROT':  # SWAP
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op[0] == 'ROT':  # TUCK: insert copy of top before [-2]
            top = stack[-1]
            stack.insert(-2, top)
        elif op[0] == 'ZERO':
            stack.pop()
            stack.append(0)
    return stack

print("Expected values for W=0 and W=1:")
print(f"{'Addr':>4} {'V':>12} {'W=0':>12} {'W=0 hex':>12} {'W=1':>12} {'W=1 hex':>12}")
print("-" * 70)

for addr, V, ops in blocks:
    results = {}
    for W in range(2):
        # After PUSH V; DUP; ZERO; FUTEX_WAKE; ROT
        stack = [W, V, W]
        execute(stack, ops)
        assert len(stack) == 1, f"addr={addr}, W={W}, stack={stack}"
        results[W] = stack[0]

    print(f"{addr:>4} {V:>12} {results[0]:>12} {results[0]:>12x} {results[1]:>12} {results[1]:>12x}")

print("\n\nAs Python arrays:")
for W in range(2):
    vals = []
    for addr, V, ops in blocks:
        stack = [W, V, W]
        execute(stack, ops)
        vals.append(stack[0])
    print(f"EXPECTED_W{W} = {vals}")
