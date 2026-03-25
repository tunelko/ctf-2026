# FlagFactory Pro — BSidesSF 2026

**CTF**: BSidesSF 2026
**Category**: Reversing / Crypto
**Author**: symmetric
**Flag**: `CTF{circuit_network_combinator}`

---

## TL;DR

A "FlagFactory Pro" binary with an expired trial requires a registration key to unlock `makeflag`. The binary generates a randomized boolean circuit as a "registration request". Reverse the gate types, parse the circuit from the base64 blob, solve the boolean satisfiability problem with Z3, and encode the solution as a product key.

---

## Challenge Description

> Shoot, the trial on our copy of FlagFactory Pro expired right before we needed it for the CTF! Can you help?

The binary `ffpro` is an x86-64 ELF that:
1. Reads `flag.txt` and `banner.txt`
2. Shows a "Trial Expired" warning
3. Offers commands: `help`, `makeflag` (licensed only), `register`, `exit`
4. `register` outputs a base64-encoded "Registration Request" (a boolean circuit)
5. Expects a product key that satisfies the circuit
6. On success, `makeflag` prints the flag

---

## Analysis

### Product Key Format

From `parse_product_key`:
- Length must be exactly 29 characters
- Dashes at positions 5, 11, 17, 23: `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`
- 25 non-dash characters, each decoded via `base32_value`
- Custom base32 charset: `A-Z` (values 0-25) + `0-5` (values 26-31)
- Each character provides 5 bits (MSB first), total = 125 bits

### Circuit Structure

From `build_circuit_blob` and `validate_key_bits`:
- The registration request is a base64-encoded blob of 1500 bytes
- Contains 250 gates, each 6 bytes: `input_a(2B) | input_b(2B) | gate_type(1B) | expected_output(1B)`
- Wires 0-124 = the 125 input bits from the product key
- Each gate reads two wires and produces a new wire (wire 125+i)
- The gate output is compared against the expected output — all 250 must match

### Gate Types

From `apply_gate` (switch on 8 cases):

| Type | Operation | Logic |
|------|-----------|-------|
| 0 | `a & b` | AND |
| 1 | `a \| b` | OR |
| 2 | `a ^ b` | XOR |
| 3 | `!(a & b)` | NAND |
| 4 | `!(a \| b)` | NOR |
| 5 | `a == b` | XNOR |
| 6 | `!a \| b` | IMPLY (a -> b) |
| 7 | `a & !b` | INHIBIT |

### Validation Flow

```
validate_key_bits(key_bits[125], expected[375], gates[250*6]):
    wires[0..124] = key_bits[0..124]
    for i in 0..249:
        gate = gates[i]
        result = apply_gate(wires[gate.a], wires[gate.b], gate.type)
        wires[125+i] = result
        if result != expected[125+i]:
            return INVALID
    return VALID
```

---

## Solve

The problem reduces to boolean satisfiability: find 125 input bits such that all 250 gate outputs match the expected values. Z3 handles this trivially.

```python
from pwn import *
import base64, struct
from z3 import *

io = remote('host', port)
io.recvuntil(b'ffpro> ')
io.sendline(b'register')
data = io.recvuntil(b'Enter registration key: ').decode()

# Extract base64 blob
start = data.find('-----BEGIN REGISTRATION REQUEST-----')
end = data.find('-----END REGISTRATION REQUEST-----')
blob = base64.b64decode(data[start+36:end].strip().replace('\n', ''))

# Parse 250 gates (6 bytes each)
gates = []
for i in range(0, len(blob), 6):
    a = struct.unpack('>H', blob[i:i+2])[0]
    b = struct.unpack('>H', blob[i+2:i+4])[0]
    gt, exp = blob[i+4], blob[i+5]
    gates.append((a, b, gt, exp))

# Z3 SAT solve
bits = [Bool(f'b{i}') for i in range(125)]
wires = list(bits)

def gate_op(a, b, t):
    ops = [And, Or, Xor,
           lambda a,b: Not(And(a,b)),
           lambda a,b: Not(Or(a,b)),
           lambda a,b: a == b,
           lambda a,b: Or(Not(a), b),
           lambda a,b: And(a, Not(b))]
    return ops[t](a, b)

solver = Solver()
for a, b, gt, exp in gates:
    r = gate_op(wires[a], wires[b], gt)
    wires.append(r)
    solver.add(r == BoolVal(bool(exp)))

assert solver.check() == sat
m = solver.model()

# Encode as product key
kb = [1 if is_true(m[bits[i]]) else 0 for i in range(125)]
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
kc = [CHARSET[sum(kb[i+j] << (4-j) for j in range(5))] for i in range(0, 125, 5)]
k = ''.join(kc)
key = f"{k[0:5]}-{k[5:10]}-{k[10:15]}-{k[15:20]}-{k[20:25]}"

io.sendline(key.encode())
io.recvuntil(b'ffpro> ')
io.sendline(b'makeflag')
print(io.recvall(timeout=5).decode())
```

---

## Key Lessons

- Boolean circuit satisfiability → Z3 is instant for 125 variables / 250 clauses
- Always verify the exact charset for key encoding — this used `A-Z0-5` not standard base32 `A-Z2-7`
- The NAND vs XNOR distinction in gate type 3 caused initial UNSAT until correctly reversed
- Registration request is randomized per connection, so the solve must be online
