#!/usr/bin/env python3
import base64, struct
from z3 import *

blob_b64 = """AAAAAAABAAQAAQEBAAIABAUBAAMAAAIAAAIAAgIAAAIAAAMAAAQAAwIAAAAAAwEBAAAAAAUB
AAAAAgMAAAUAgQMBAAkAfQYBAAUAgQEBAAgAfQABAAcAgAAAAAgAgAMBAAcAhAcAAAcAhgAA
AAkAggEBAAgAgwYAAAwAjgMBAAoAiQIBAAoAjwcAAAsAjwMBAAsAjQAAAAsAjQQBAAwAiAYB
AAwAjwcAAAsAiwcAAAwAigQAABAAkwcBABEAmQEBABEAkQIAABIAlQIAAA8AmAQBAA8AlgUA
ABEAlQYAABMAlQQBABAAlAYBABMAkgAAABYAoQEBABUApAUAABQAogIAABUAoQAAABYAogEB
ABYAmwQAABQAoQEBABQAngUAABYAoAQAABcAngAAABoArAIBABwAqwQAABoApQEBABsAqwQA
ABoAqgEBABwAqgEBABkApQMBABkAqAMBABkAqgUBAB0AqgQAAB8AtAYBACEAuAAAAB8AtAEB
ACEAtwQAACEAsQIAACAAsgMBACIAtwQAACEAtQQAAB4ArwYBAB4AtgUAACQAugUAACcAvQMB
ACYAwAMBACQAvQIBACMAwAMBACYAuwUBACcAvgcAACYAuQcAACQAugQAACQAuQIAACsAygIB
ACsAywQAACoAywMBACsAywcBACkAyAcAACsAzAcBACgAyAMBACsAywYAACkAwwIAACwAwwEA
ADAAzQMAAC4A1gAAAC8AzgEBAC8AzwIAAC4A0gcAADAA1AYAADAA1gIBAC4A0wMAADAAzwYB
AC4A1QAAADIA3AQAADUA2AMBADIA2AAAADIA2gQAADMA3gAAADIA3wABADUA3AEBADUA1wEB
ADUA1wQAADYA4AQAADsA4gAAADcA5AQAADgA5AUAADcA6gMBADkA4QMBADcA5wQAADgA6AcA
ADoA5QYBADkA5AUBADsA5AIAAD4A8wcAAEAA6wUAAD4A8wcAAD8A8wQAAD4A8AIAAEAA7gUB
AD8A8gMBADwA7wMAADwA7AYAAD0A7AAAAEMA9gYAAEIA/gQAAEIA9QQAAEUA+AAAAEUA9QMB
AEIA+wcAAEMA9gQAAEEA+AcBAEMA+wcAAEEA9wcBAEcBBgUBAEoBBAcBAEgBAwYBAEkBCAYB
AEkBAAAAAEYBAQUBAEcA/wQAAEkBBQIAAEkBBQEAAEkBAQIAAE8BDQAAAE8BEgMBAEwBDwUB
AEsBDQAAAEsBCQIAAE4BCwMBAE8BEQQBAEsBEQUAAE0BDQAAAE8BCgYBAFEBFgIBAFQBGwYA
AFABFwYBAFABFgUBAFIBFgEBAFMBEwMBAFABFAUAAFABFAAAAFABFAQAAFIBFwYAAFkBJQIA
AFUBJgIBAFYBJAQBAFkBHgEAAFUBIgMAAFYBIAcAAFkBIAUAAFkBIQMBAFUBIgUBAFcBHQMA
AFwBMAAAAF4BLQQBAF0BLAcBAF0BJwEBAFsBKgYBAFsBKgIAAF4BLwAAAF0BMAcBAFsBLQAA
AFoBMAAAAGIBOQcAAGEBMgAAAGMBNQIAAGMBOQcBAGEBOAEBAGIBNgUBAGIBOQcAAGEBNQEB
AGIBOgQBAF8BNAMAAGgBOwIBAGgBPgQAAGgBRAYAAGQBQQcAAGgBPgUBAGcBOwYBAGQBRAQB
AGUBPwQAAGYBQAQAAGYBPAIAAGkBSQEBAG0BSwQAAG0BSgIAAGkBSAEAAG0BRQIAAGsBRgEB
AGwBSQEBAG0BTQUAAGkBRQUAAGoBSgQAAHEBVQIAAG8BUQcAAHABVAMAAHIBUgUAAG8BWAYB
AHABVgMBAHABVgUAAHABUAYAAHEBVAQAAHEBVwIBAHUBWwIBAHMBYAEBAHYBXwUAAHYBYQAA
AHYBYAcBAHYBXQQAAHYBWwQAAHMBXgABAHQBYgMAAHQBWQYAAHsBZwMBAHsBagYBAHgBZwAA
AHgBZgUBAHwBZQUAAHsBawYBAHsBagEBAHoBZQQAAHkBaAcAAHgBawUB"""

blob = base64.b64decode(blob_b64)
gates = []
for i in range(0, len(blob), 6):
    a = struct.unpack('>H', blob[i:i+2])[0]
    b = struct.unpack('>H', blob[i+2:i+4])[0]
    gate_type = blob[i+4]
    expected = blob[i+5]
    gates.append((a, b, gate_type, expected))

print(f"Parsed {len(gates)} gates")

# Z3 solver
bits = [Bool(f'b{i}') for i in range(125)]
wires = list(bits)  # wires 0-124 are inputs

def gate_op(a_val, b_val, gtype):
    if gtype == 0: return And(a_val, b_val)
    elif gtype == 1: return Or(a_val, b_val)
    elif gtype == 2: return Xor(a_val, b_val)
    elif gtype == 3: return Not(Xor(a_val, b_val))  # XNOR
    elif gtype == 4: return Not(Or(a_val, b_val))    # NOR
    elif gtype == 5: return a_val == b_val            # EQ/XNOR
    elif gtype == 6: return Or(Not(a_val), b_val)     # IMPLY (NOT a OR b)
    elif gtype == 7: return And(a_val, Not(b_val))    # AND NOT
    return False

solver = Solver()
for i, (a, b, gtype, expected) in enumerate(gates):
    a_val = wires[a] if a < len(wires) else BoolVal(False)
    b_val = wires[b] if b < len(wires) else BoolVal(False)
    result = gate_op(a_val, b_val, gtype)
    wires.append(result)
    if expected:
        solver.add(result == True)
    else:
        solver.add(result == False)

print("Solving...")
if solver.check() == sat:
    model = solver.model()
    key_bits = []
    for i in range(125):
        val = model[bits[i]]
        key_bits.append(1 if is_true(val) else 0)

    # Convert 125 bits to base32 key (25 chars, 5 bits each)
    B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    key_chars = []
    for i in range(0, 125, 5):
        val = 0
        for j in range(5):
            val = (val << 1) | key_bits[i+j]
        key_chars.append(B32[val])

    key = ''.join(key_chars)
    formatted = f"{key[0:5]}-{key[5:10]}-{key[10:15]}-{key[15:20]}-{key[20:25]}"
    print(f"Key: {formatted}")
else:
    print("UNSAT!")
