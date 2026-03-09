#!/usr/bin/env python3
"""
Challenge: Wasmbler — upCTF 2026
Category:  rev (WebAssembly custom VM)

Custom stack-based VM in WASM with 13 operations and Fisher-Yates shuffled dispatch table.
Solve by extracting constraints from the bytecode and solving with z3.
"""
from z3 import *

# Flag is 38 bytes: upCTF{...}
flag = [BitVec(f'f{i}', 8) for i in range(38)]

solver = Solver()

# Known prefix/suffix
for i, c in enumerate(b'upCTF{'):
    solver.add(flag[i] == c)
solver.add(flag[37] == ord('}'))

# Printable ASCII constraints
for i in range(6, 37):
    solver.add(flag[i] >= 0x20, flag[i] <= 0x7e)

# Helper: ROL/ROR on 8-bit bitvectors
def rol8(x, n):
    n = n & 7
    return (x << n) | (LShR(x, 8 - n)) if n else x

def ror8(x, n):
    n = n & 7
    return (LShR(x, n)) | (x << (8 - n)) if n else x

# Constraints extracted from opcode trace:
# Format per check block:
#   Single: LOAD_NEXT(idx), LOAD_INPUT, [LOAD_NEXT(const), OP], LOAD_NEXT(expected), CMP_EQ, AND
#   Double: LOAD_NEXT(idx1), LOAD_INPUT, LOAD_NEXT(idx2), LOAD_INPUT, OP, ...

# Block 0: input[13] ROL 5 == 174
solver.add(rol8(flag[13], 5) == 174)

# Block 1: input[35] ROR 6 == 196
solver.add(ror8(flag[35], 6) == 196)

# Block 2: input[14] - input[28] == input[37] + 83 (mod 256)
# Actually: (input[14] - input[28]) CMP_EQ (input[37] + 83)
# Stack: push 14, LOAD_INPUT -> f[14], push 28, LOAD_INPUT -> f[28], SUB -> f[14]-f[28]
#         push 37, LOAD_INPUT -> f[37], push 83, ADD -> f[37]+83
#         CMP_EQ -> (f[14]-f[28]) == (f[37]+83)
solver.add((flag[14] - flag[28]) == (flag[37] + 83))

# Block 3: input[27] ROR 2 == 12
solver.add(ror8(flag[27], 2) == 12)

# Block 4: input[21] ROL 4 == 214
solver.add(rol8(flag[21], 4) == 214)

# Block 5: input[36] + input[12] CMP_EQ input[4] + 143
# Stack: push 36, INP -> f[36], push 12, INP -> f[12], ADD -> f[36]+f[12]
#         push 4, INP -> f[4], push 143, ADD -> f[4]+143
#         CMP_EQ
solver.add((flag[36] + flag[12]) == (flag[4] + 143))

# Block 6: input[10] XOR input[23] == 51
solver.add(flag[10] ^ flag[23] == 51)

# Block 7: input[10] SHL 2 == 124
solver.add((flag[10] << 2) == 124)

# Block 8: input[25] XOR input[17] == 107
solver.add(flag[25] ^ flag[17] == 107)

# Block 9: input[31] ROR 6 == 220
solver.add(ror8(flag[31], 6) == 220)

# Block 10: input[9] XOR input[16] == 59
solver.add(flag[9] ^ flag[16] == 59)

# Block 11: input[37] XOR input[25] CMP_EQ input[23] + 182
# Stack: push 37, INP, push 25, INP, XOR -> f[37]^f[25]
#         push 23, INP, push 182, ADD -> f[23]+182
#         CMP_EQ
solver.add((flag[37] ^ flag[25]) == (flag[23] + 182))

# Block 12: input[5] - input[3] CMP_EQ input[7] + 244
solver.add((flag[5] - flag[3]) == (flag[7] + 244))

# Block 13: input[4] AND input[24] CMP_EQ input[29] + 157
solver.add((flag[4] & flag[24]) == (flag[29] + 157))

# Block 14: input[7] - input[18] CMP_EQ input[27] + 144
solver.add((flag[7] - flag[18]) == (flag[27] + 144))

# Block 15: input[32] MOD input[11] == 102
# MOD uses (divisor | 1), and it's i32.rem_s
# But since values are bytes 0-255, rem_s acts as unsigned for positive values
solver.add(URem(flag[32], (flag[11] | 1)) == 102)

# Block 16: input[9] ROR 2 == 25
solver.add(ror8(flag[9], 2) == 25)

# Block 17: input[20] SHL 1 == 102
solver.add((flag[20] << 1) == 102)

# Block 18: input[19] XOR input[15] CMP_EQ input[3] + 195
solver.add((flag[19] ^ flag[15]) == (flag[3] + 195))

# Block 19: input[28] XOR input[33] CMP_EQ input[7] + 35
solver.add((flag[28] ^ flag[33]) == (flag[7] + 35))

# Block 20: input[34] ROL 5 == 76
solver.add(rol8(flag[34], 5) == 76)

# Block 21: input[15] - input[30] CMP_EQ input[26] + 162
solver.add((flag[15] - flag[30]) == (flag[26] + 162))

# Block 22: input[22] OR input[27] CMP_EQ input[26] + 15
solver.add((flag[22] | flag[27]) == (flag[26] + 15))

# Block 23: input[15] ROL 5 == 140
solver.add(rol8(flag[15], 5) == 140)

# Block 24: input[8] XOR input[27] CMP_EQ input[11] + 207
solver.add((flag[8] ^ flag[27]) == (flag[11] + 207))

# Block 25: input[32] + input[33] CMP_EQ input[10] + 57
solver.add((flag[32] + flag[33]) == (flag[10] + 57))

# Block 26: input[6] + input[8] CMP_EQ input[16] + 129
solver.add((flag[6] + flag[8]) == (flag[16] + 129))

# Block 27: input[12] ROR 4 == 23
solver.add(ror8(flag[12], 4) == 23)

# Block 28: input[24] SHL 2 == 204
solver.add((flag[24] << 2) == 204)

# Block 29: input[22] - input[23] == 246
solver.add((flag[22] - flag[23]) == 246)

# Block 30: input[26] + input[7] CMP_EQ input[8] + 36
solver.add((flag[26] + flag[7]) == (flag[8] + 36))

# Also the first value pushed is 1 (initial accumulator)
# op 0: LOAD_NEXT(1) — this pushes 1 onto stack before all the ANDs

print("Solving...")
if solver.check() == sat:
    model = solver.model()
    result = bytes([model.eval(flag[i]).as_long() for i in range(38)])
    print(f"FLAG: {result.decode()}")
else:
    print("UNSAT - checking constraints...")
    # Debug: check each constraint individually
    for i, c in enumerate(solver.assertions()):
        s2 = Solver()
        s2.add(c)
        if s2.check() != sat:
            print(f"  Constraint {i} is UNSAT by itself: {c}")
