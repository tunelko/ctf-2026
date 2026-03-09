#!/usr/bin/env python3
"""
DiceCTF 2026 - interpreter-required (Rev)
Solver: Evaluates the custom Chinese/Wenyan-style lambda calculus program
to extract the flag without running the actual (OOM-prone) interpreter.

The binary implements an untyped lambda calculus interpreter using Church encodings.
The flag_riddle.txt encodes a program that computes the flag using:
  - Church numerals encoded as binary (LSB-first) using 春(0)/秋(1) bits
  - 朝...暮 delimiters for number literals
  - Arithmetic: 合(add), 次(mul), 销(sub), 幂(exp), 阶(factorial), 分(div)
  - Result is a linked list of Church numerals representing char codes
"""

import re, math, sys

def solve(filepath):
    with open(filepath, 'r') as f:
        text = f.read()

    # Extract only CJK characters (matching the binary's filter ranges)
    clean = ''
    for c in text:
        cp = ord(c)
        if (0x4E00 <= cp <= 0x9FFF or
            0x3200 <= cp <= 0x4DBF or
            0x2E80 <= cp <= 0x2FDF or
            0x2FF0 <= cp <= 0x303F or
            0x31C0 <= cp <= 0x31EF or
            0xF900 <= cp <= 0xFAFF):
            clean += c

    # Parse number literals: X为朝<bits>暮 -> LSB-first binary
    # 春 = bit 0, 秋 = bit 1
    all_vals = {}
    for m in re.finditer(r'([\u3400-\u9fff])为朝([春秋]+)暮', clean):
        name = m.group(1)
        if name not in all_vals:
            bits = [0 if b == '春' else 1 for b in m.group(2)]
            all_vals[name] = sum(b * (2**i) for i, b in enumerate(bits))

    # Parse operation definitions
    ops = {}
    for m in re.finditer(r'([\u3400-\u9fff])为阶([\u3400-\u9fff])矣', clean):
        name = m.group(1)
        if name not in all_vals and name not in ops:
            ops[name] = ('阶', m.group(2))  # factorial

    for op in ['销', '幂', '分', '合', '次']:
        for m in re.finditer(r'([\u3400-\u9fff])为' + op + r'([\u3400-\u9fff])([\u3400-\u9fff])矣', clean):
            name = m.group(1)
            if name not in all_vals and name not in ops:
                ops[name] = (op, m.group(2), m.group(3))

    # Evaluate expressions
    # 合=add, 次=mul, 销=sub, 幂=exp, 阶=factorial, 分=div
    memo = {}
    def ev(name):
        if name in memo:
            return memo[name]
        if name in all_vals:
            memo[name] = all_vals[name]
            return all_vals[name]
        if name not in ops:
            return None
        op = ops[name]
        try:
            if op[0] == '阶':
                a = ev(op[1])
                if a is None or a > 1000: return None
                result = math.factorial(a)
            elif op[0] == '合':
                a, b = ev(op[1]), ev(op[2])
                if None in (a, b): return None
                result = a + b
            elif op[0] == '次':
                a, b = ev(op[1]), ev(op[2])
                if None in (a, b): return None
                result = a * b
            elif op[0] == '幂':
                a, b = ev(op[1]), ev(op[2])
                if None in (a, b): return None
                result = a ** b
            elif op[0] == '销':
                a, b = ev(op[1]), ev(op[2])
                if None in (a, b): return None
                result = max(0, a - b)  # Church subtraction floors at 0
            elif op[0] == '分':
                a, b = ev(op[1]), ev(op[2])
                if None in (a, b) or b == 0: return None
                result = a // b  # integer division
            else:
                return None
            memo[name] = result
            return result
        except:
            return None

    # Extract flag list: 于双为有X矣 pattern
    flag_chars = [m.group(1) for m in re.finditer(r'于双为有([\u3400-\u9fff])矣', clean)]

    # Evaluate and print
    output = []
    for fc in flag_chars:
        v = ev(fc)
        if v is not None:
            output.append(chr(v))
        else:
            output.append('?')

    result = ''.join(output)
    print(result)

    # Extract just the flag
    import re as re2
    flag_match = re2.search(r'dice\{[^}]+\}', result)
    if flag_match:
        print(f"\nFLAG: {flag_match.group()}")

if __name__ == '__main__':
    solve(sys.argv[1] if len(sys.argv) > 1 else 'flag_riddle.txt')
