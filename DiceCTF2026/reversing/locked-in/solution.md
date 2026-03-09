# locked-in

| Field       | Value                |
|-------------|----------------------|
| Platform    | diceCTF 2026         |
| Category    | rev                  |
| Difficulty  | Hard                 |

## Description
> A custom VM flag verifier. Can you unlock the flag?

## TL;DR
Custom stack-based VM with 16 threads communicating via futex-based IPC channels. Each flag character is XOR-encrypted with a per-position key, reversed, then run through a 5-stage transform pipeline. The transformed byte drives a state machine (4 two-bit operations per char) with AND-mask validity checks against 16 precomputed expected bitmasks. BFS over the 528-state space across 30 processing steps recovers the flag.

## Initial Analysis

### File Reconnaissance
```bash
$ file locked_in
locked_in: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked,
BuildID[sha1]=19e3c4f5094d048596571bbe1e2693c6e2cffa4c, for GNU/Linux 3.2.0, stripped

$ file flag_verifier.bin
flag_verifier.bin: data

$ ls -la flag_verifier.bin
-rw-r--r-- 1 student student 43360 ... flag_verifier.bin
# 43360 / 8 = 5420 int64 values

$ echo 'dice{AAAAAAAAAAAAAAAAAAAAAAAA}' | ./locked_in flag_verifier.bin
Dice Flag Verifier
locking in...
[locked in] enter flag:
Flag rejected

$ echo 'dice{AAAAAAAAAAAAAAAAAAAAAAAA}' | strace -f -e trace=write ./locked_in flag_verifier.bin 2>&1 | head -5
[pid 180057] write(1, "D", 1)    # outputs char-by-char (putchar via VM)
```

The binary is a stripped, statically-linked x86-64 ELF. It loads `flag_verifier.bin` as bytecode for a custom VM. The VM uses `clone3` to spawn 16 threads and Linux `futex` syscalls for inter-thread synchronization.

### Bytecode disassembly

Wrote `disasm.py` — identifies 32 opcodes, 4 of which (PUSH, JZ, JNZ, CALL) take a following u64 operand:

```bash
$ python3 disasm.py flag_verifier.bin > /tmp/locked_disasm.txt
; 4276 instructions from 5420 u64 values

$ head -20 /tmp/locked_disasm.txt
    0 [u    0]: PUSH                  137  ; 0x89
    1 [u    2]: PUSH            2147483647  ; 0x7fffffff
    2 [u    4]: DUP
    3 [u    5]: ZERO
    4 [u    6]: FUTEX_WAKE
    5 [u    7]: ROT
    ...
```

32 opcodes identified:
```
0: FUTEX_WAIT_BS   8: DUP      16: ADD    24: JZ
1: FUTEX_WAKE      9: OVER     17: SUB    25: JNZ
2: FUTEX_WAIT     10: ROT      18: MUL    26: CALL
3: FUTEX_WAKE_N   11: RROT     19: DIV    27: HALT_FALSE
4: THREAD         12: NOP      20: AND    28: GETCHAR
5: HALT_TRUE      13: INC      21: OR     29: PUTCHAR
6: PUSH           14: DEC      22: XOR    30: LOAD
7: POP            15: ZERO     23: NOT    31: STORE
```

### VM architecture — Stack semantics

Critical stack operations determined through bytecode pattern analysis:

- **ROT (opcode 10) = TUCK**: `[a, b] → [b, a, b]` — duplicates top and inserts before second. Implemented as `stack.insert(-2, stack[-1])`.
- **RROT (opcode 11) = SWAP**: swaps top two elements.
- **CALL/HALT_FALSE**: separate call stack (not on data stack). CALL saves return PC; HALT_FALSE returns to caller.

### Thread structure discovery

Scanning the disassembly for `THREAD` (opcode 4) markers reveals 16 threads, each separated by HALT_FALSE boundaries. Key subroutines identified:

| Thread | Subroutine | Channel | Function |
|--------|-----------|---------|----------|
| Init | insns 0-935 | N/A | Compute expected values, store in mem[137]-mem[152] |
| sub_1179 | insn 1179 | 'R','V' | Relay: pack/unpack state |
| sub_1201 | insn 1201 | 'f' | **Main processor**: apply 4 ops per char |
| sub_1252 | insn 1252 | 'Z' | **Final check**: packed XOR 0xE00000002 == 0? |
| sub_1266 | insn 1266 | '>' | Conditional XOR transform stage |
| sub_1288 | insn 1288 | 'r' | XOR 0x5A transform stage |
| sub_1300 | insn 1300 | 'n' | ROL 1 transform stage |
| sub_1319 | insn 1319 | 'J' | **Pipeline coordinator**: J → r → n → r → > → r → f |
| sub_1339 | insn 1339 | N/A | Calls sub_1344 then loops |
| sub_1344 | insn 1344 | 'j','B','J' | **Input collector**: read + XOR relay + reverse send |
| sub_1397 | insn 1397 | 'F' | Result printer (accepted/rejected) |
| sub_1463 | insn 1463 | 'j' | **XOR relay**: per-position XOR keys |

### Channel protocol

Each channel `ch` uses 4 memory slots:
```
mem[ch*4 + 0] = mutex (futex address for locking)
mem[ch*4 + 1] = data_ready flag
mem[ch*4 + 2] = signal flag
mem[ch*4 + 3] = data payload
```

Three channel primitives:
- **sub_4195** (receive): lock ch → wait for data_ready → read mem[ch+3] → clear flags → unlock → return data
- **sub_4102** (send): lock ch → wait until slot free → write data to mem[ch+3] → set data_ready → unlock → wake waiters
- **sub_4098** (send_ack): ROT to save channel → CALL send → CALL receive → return response
- **sub_4232** (ack): similar to send, writes response data back
- **sub_4262** (lock): FUTEX_WAIT_BS loop on channel address
- **sub_4273** (unlock): FUTEX_WAKE on channel address

## Solution Process

### Step 1: Expected value computation (FUTEX_WAKE return value W)

The initialization block (insns 0-935) computes 16 expected values and stores them at mem[137]-mem[152]. Each computation follows a pattern:

```
PUSH V; DUP; ZERO; FUTEX_WAKE; ROT; <arithmetic on W>; MUL; RROT; <more arithmetic>; ADD; PUSH addr; STORE
```

The `FUTEX_WAKE` instruction returns a value W (the number of threads woken). This W is used as a parameter in the computation.

Wrote `compute_expected.py` to symbolically evaluate each block for W=0 and W=1:

```bash
$ python3 compute_expected.py
Expected values for W=0 and W=1:
Addr            V         W=0     W=0 hex         W=1     W=1 hex
----------------------------------------------------------------------
 137   2147483647  2147483647    7fffffff  4294967295    ffffffff
 138    306790510   920371530    36d804ea  2147533571    8000c303
 ...
```

Key question: what is W at runtime? The Linux `futex(FUTEX_WAKE)` syscall returns the number of threads woken, which is typically 0 (no waiters yet during init) or 1.

### Step 2: Extracting actual expected values via GDB

To determine W definitively, used GDB to dump VM memory after the binary finishes:

```bash
$ echo 'dice{AAAAAAAAAAAAAAAAAAAAAAAA}' > /tmp/locked_input.txt

# GDB script: catch exit_group, search for expected value pattern
$ gdb -batch -x /tmp/gdb_extract.py ./locked_in
```

GDB script searched for `0xFFFFFFFF` values in memory that are 120 bytes apart (expected[0] and expected[15]):

```
Potential match: 0x4d5f98 and 0x4d6010 (diff=120)
0x4d5f98: 0x00000000ffffffff  0x000000008000c303
0x4d5fa8: 0x00000000aeee9859  0x00000000a8aaa725
...
```

**Result: W=1 confirmed.** The runtime values match the W=1 computation exactly.

VM memory base = `0x4d5f98 - 137*8 = 0x4d5b50`.

Additional memory dump:
```
mem[49]  = 0x40000     (state-related)
mem[65]  = 7           (constant)
mem[73]  = 14          (constant)
mem[85]  = packed(7, 0x40000)  (final state after processing test input)
```

### Expected values (W=1)
```
expected[0]  = 0xFFFFFFFF    expected[8]  = 0x9FFF2229
expected[1]  = 0x8000C303    expected[9]  = 0xD10255E5
expected[2]  = 0xAEEE9859    expected[10] = 0x95AA8813
expected[3]  = 0xA8AAA725    expected[11] = 0xD1282ACB
expected[4]  = 0xA8ACA889    expected[12] = 0x95654AA9
expected[5]  = 0xA8AA8261    expected[13] = 0xA555AAB5
expected[6]  = 0xAEEAFF2F    expected[14] = 0x88042205
expected[7]  = 0xA00088A9    expected[15] = 0xFFFFFFFF
```

### Step 3: Initial and target states

**Initial state** — from sub_1201 (main processor init):
```
insn 1202: PUSH 5726666752   ; V = 0x155560000
insn 1203-1212: compute V*(W+2) = 5726666752 * 3 = 17180000256 = 0x400020000
               → h=4, l=0x20000 (2^17)
```

**Target state** — from sub_1252 (final check):
```
insn 1257: PUSH 60129542146  ; = 0xE00000002
insn 1258: XOR               ; packed ^ 0xE00000002
insn 1259: JZ                ; if zero → accepted
               → target = packed(14, 2), i.e. h=14, l=2 (2^1)
```

### Step 4: Per-position XOR keys (sub_1463)

Sub_1463 is a relay thread that receives characters on channel 'j' (106), XORs each with a dynamically-computed per-position key, and acks back with the XORed result.

Each key is computed using the same `PUSH V; DUP; ZERO; FUTEX_WAKE; ROT; <arithmetic>; ADD` pattern as the expected values, with W=1.

Emulated sub_1463 with a Python stack VM, feeding dummy chars:

```bash
$ python3 -c "
# (emulator code - see solve_final.py for full implementation)
# Feeds dummy 0x41 chars, tracks XOR keys applied at each position
"
```

Output (first 30 positions before infinite `^ 0` loop):
```
[ 0] RECV ch=106 -> XOR 237 (0xed) -> ACK ch=106
[ 1] RECV ch=106 -> XOR 147 (0x93) -> ACK ch=106
[ 2] RECV ch=106 -> XOR 150 (0x96) -> ACK ch=106
...
[29] RECV ch=106 -> XOR 145 (0x91) -> ACK ch=106
[30] RECV ch=106 -> XOR  99 (0x63) -> ACK ch=106  # "cor easter egg" starts
```

After position 29, keys spell ASCII "cor easter egg" then enter an infinite `^ 0` loop — only the first 30 matter.

**XOR keys:**
```python
XOR_KEYS = [237, 147, 150, 156, 205, 207, 115, 85, 41, 22,
            159, 196, 170, 155, 75, 246, 180, 122, 177, 230,
            252, 218, 150, 186, 145, 87, 65, 30, 81, 145]
```

### Step 5: Data flow — input collector (sub_1344)

Tracing the stack through sub_1344's disassembly:

1. **Input loop** (insns 1347-1361):
   - `GETCHAR` → read one char
   - Check for newline (10) or EOF (-1): if so, break
   - `PUSH 'j' (106); CALL 4098` → send char to channel 'j' (sub_1463's XOR relay), receive XORed char back
   - `RROT; INC` → swap XORed char under counter, increment counter
   - Loop

   After 30 chars, stack: `[sync, xored_0, xored_1, ..., xored_29, 30]`

2. **Length check** (insns 1362-1366):
   - `DUP; PUSH 30; XOR; JNZ error` → reject if count ≠ 30

3. **Reverse send loop** (insns 1367-1377):
   - `RROT` → bring next xored char to top (from deepest remaining)
   - `PUSH 'J' (74); CALL 4098` → send to channel 'J' (pipeline coordinator)
   - `RROT; DEC` → decrement counter
   - Loop until counter = 0

   **Order**: xored_29 sent first, xored_0 sent last → **REVERSE order**

### Step 6: Transform pipeline (sub_1319)

Sub_1319 receives each char from channel 'J' and sends through 5 relay threads:

```
'J' → 'r' (XOR 0x5A) → 'n' (ROL 1) → 'r' (XOR 0x5A) → '>' (conditional) → 'r' (XOR 0x5A) → 'f' (processor)
```

Each relay thread's transform, from disassembly:

**Thread 'r'** (sub_1288): `x = (x ^ 0x5A) & 0xFF`

**Thread 'n'** (sub_1300): `x = ((x << 1) | (x >> 7)) & 0xFF` (rotate left 1 bit)

**Thread '>'** (sub_1266):
```python
if x & 1:    # odd
    x = (x ^ (2 * x)) & 0xFF
else:         # even
    x = (x ^ 0xFE) & 0xFF
```

Combined:
```python
def transform_char(c):
    x = (c ^ 0x5A) & 0xFF
    x = ((x << 1) | (x >> 7)) & 0xFF
    x = (x ^ 0x5A) & 0xFF
    x = (x ^ (2*x if x&1 else 0xFE)) & 0xFF
    x = (x ^ 0x5A) & 0xFF
    return x
```

### Step 7: State machine (sub_1201 / sub_4027)

The processor thread (sub_1201) receives a transformed byte from channel 'f' and applies 4 operations, one per 2-bit pair (LSB first):

```
pair = 0: h--   (decrement high word)
pair = 1: h++   (increment high word)
pair = 2: l*=2  (shift low word left; overflow increments h)
pair = 3: l//=2 (shift low word right)
```

**Validity check per operation** (sub_4027, using sub_4038 for LOAD):
```python
if 0 <= new_h <= 15 and (expected[new_h] & new_l) == 0:
    state = (new_h, new_l)  # accepted
# else: state unchanged (rejected)
```

State space: h ∈ [0,15], l is always a power of 2 (or 0) → 16 × 33 = 528 states.

### Step 8: Model verification

Before solving, verified the model against GDB-extracted final states for two test inputs:

```bash
# Test 1: dice{AAAAAAAAAAAAAAAAAAAAAAAA}
# Model predicts: h=7, l=0x40000
# GDB shows: mem[85] = packed(7, 0x40000) = 30065033216  ✓

# Test 2: dice{BBBBBBBBBBBBBBBBBBBBBBBB}
# Model predicts: h=7, l=0x10000
# GDB shows: mem[85] = packed(7, 0x10000) = 30064836608  ✓
```

Both match. Model is correct.

### Step 9: BFS solver

Full data flow for flag position `p` (0-indexed), processing step `i = 29 - p`:
```
flag[p] → XOR key[p] → (reversed) → transform_char() → 4 state operations
```

BFS over 30 steps. At each step, the available transforms depend on the flag position (due to per-position XOR keys):
- Step `i` processes flag position `pos = 29 - i`
- XOR key = `XOR_KEYS[pos]`
- For each printable ASCII char `c`: `tb = transform_char(c ^ XOR_KEYS[pos])`

```bash
$ python3 solve_final.py
[*] Start: h=4, l_bit=17
[*] Target: h=14, l_bit=1
  Step 5/30: 59 reachable states
  Step 10/30: 80 reachable states
  Step 15/30: 118 reachable states
  Step 20/30: 164 reachable states
  Step 25/30: 207 reachable states
  Step 30/30: 244 reachable states
[+] Target state (14, 1) is reachable!

[+] Flag: dice{y0u_w3r3_v3rY_l0Ck3d_1n!}
[+] Verified!
```

### Step 10: Binary verification

```bash
$ echo 'dice{y0u_w3r3_v3rY_l0Ck3d_1n!}' | ./locked_in flag_verifier.bin
Dice Flag Verifier
locking in...
[locked in] enter flag:
Flag accepted
```

## Discarded Approaches

1. **W=0 assumption**: First solver assumed FUTEX_WAKE returns 0 (no waiters during init). With W=0, `expected[14] & 2 ≠ 0`, making the target state h=14,l=2 impossible. Switched to W=1 after analyzing more carefully.

2. **No XOR keys**: Early solver didn't account for sub_1463's per-position XOR. The BFS found a path but produced gibberish when converted back to flag chars. Tracing sub_1463 revealed the XOR relay.

3. **No reverse order**: Initially assumed chars processed in forward order. Stack trace of sub_1344 revealed the reverse send loop (RROT to bring deepest char to top, decrementing counter).

4. **GDB memory search for expected values**: First attempts searched wrong memory regions. Eventually found by searching for two `0xFFFFFFFF` values 120 bytes apart (expected[0] and expected[15]).

5. **24 inner chars only**: Earlier model assumed `dice{` prefix and `}` suffix were processed separately. Actual binary processes all 30 characters through the same pipeline — the flag format is just part of the flag string.

## Final Exploit

**`solve_final.py`** — See full source in repo. Key components:
- `transform_char()`: 5-stage transform pipeline
- `apply_4ops()`: state machine with AND-mask validity checks
- `solve()`: BFS over (h, l_bit) state space, 30 steps, per-position XOR keys, reverse processing order

**`disasm.py`** — Bytecode disassembler for the custom VM

**`compute_expected.py`** — Symbolic evaluation of expected value computation blocks

## Execution
```bash
python3 solve_final.py          # Solver
python3 disasm.py                # Disassembler
echo 'dice{y0u_w3r3_v3rY_l0Ck3d_1n!}' | ./locked_in flag_verifier.bin  # Verify
```

## Flag
```
dice{y0u_w3r3_v3rY_l0Ck3d_1n!}
```

## Key Lessons
- **FUTEX_WAKE return value**: The return value of `futex(FUTEX_WAKE)` (= number of threads woken) is used as a runtime constant in the bytecode. Getting this wrong invalidates all derived values. GDB memory dump at process exit is the definitive way to verify.
- **Stack VM tracing**: For complex multi-threaded stack VMs, emulate each thread independently with dummy values to extract the transform logic. The stack effects of compound operations (ROT/TUCK) can be subtle.
- **Reverse processing order**: Hidden in sub_1344's stack manipulation — chars accumulated on the stack are naturally reversed when popped off for the next stage.
- **Per-position XOR keys**: Computed dynamically using the same FUTEX_WAKE-based arithmetic as the expected values. Extractable by emulating the relay thread.
- **Model verification before solving**: Comparing predicted vs GDB-extracted states for known inputs catches model errors before wasting time on wrong BFS parameters.

## References
- Linux futex(2) man page — FUTEX_WAKE return value semantics
- Stack VM implementation patterns (TUCK, SWAP as ROT, RROT)
