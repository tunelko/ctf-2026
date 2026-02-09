# Writeup: Angr-y Binary - 247CTF Reversing Challenge

## Challenge Info

- **Name**: Angr-y Binary
- **Category**: Reversing
- **Platform**: 247CTF
- **Server**: `tcp://6feef76ed083a9b2.247ctf.com:50178`
- **File**: `5dc41cb24b73f43a4da0d2190663546159e18d5b.zip`

## Challenge Description

> Why waste time creating multiple functions, when you can just use one? Can you find the path to the flag in this angr-y binary?

The "angr-y" hint clearly suggests the use of **angr**, a binary analysis and symbolic execution framework.

---

## Initial Analysis

### Binary Information

```bash
$ file angr-y_binary
angr-y_binary: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux.so.2,
for GNU/Linux 3.2.0, BuildID[sha1]=611e939f262f927b8515162283d36476df2d3244,
not stripped

$ ls -la angr-y_binary
-rwxrwxr-x 1 root root 6167948 Apr  2  2021 angr-y_binary
```

**Observations:**
- 32-bit ELF binary
- Unusually large size: ~6 MB
- Not stripped (contains symbols)

### Relevant Strings

```bash
$ strings angr-y_binary | grep -iE "flag|correct|wrong"
flag.txt
Oops, no flag for you!
give_flag
print_flag
no_flag
maybe_flag
```

### Identified Functions

```bash
$ objdump -t angr-y_binary | grep -E "main|flag|print"
0862a030 g     O .data   00000004              give_flag
0804865f g     F .text   005e0082              main
08048596 g     F .text   00000073              print_flag
08048609 g     F .text   0000001a              no_flag
08048623 g     F .text   0000003c              maybe_flag
```

**Key addresses:**

| Function | Address | Size | Description |
|---------|-----------|--------|-------------|
| `main` | 0x0804865f | 0x5e0082 (~6MB) | Main function with multiple paths |
| `print_flag` | 0x08048596 | 0x73 | Prints the flag (TARGET) |
| `no_flag` | 0x08048609 | 0x1a | Error message (AVOID) |
| `maybe_flag` | 0x08048623 | 0x3c | Intermediate function |

---

## Problem Analysis

The size of `main` (~6MB) indicates that the binary contains a **decision maze** with thousands of branches. Each decision depends on user input, and only one specific path leads to `print_flag`.

Solving this manually would be impossible. This is where **angr** shines: it can symbolically explore all possible paths and find the input that leads to the target.

### Program Flow

```
                    ┌─────────┐
                    │  main   │
                    └────┬────┘
                         │
            ┌────────────┼────────────┐
            │            │            │
            ▼            ▼            ▼
       ┌────────┐   ┌────────┐   ┌────────┐
       │ path_1 │   │ path_2 │   │ path_n │
       └────┬───┘   └────┬───┘   └────┬───┘
            │            │            │
            ▼            ▼            ▼
          ... (thousands of branches) ...
            │            │            │
            ▼            ▼            ▼
       ┌─────────┐  ┌─────────┐  ┌─────────┐
       │ no_flag │  │no_flag  │  │print_flag│ ← TARGET
       └─────────┘  └─────────┘  └─────────┘
```

---

## Solution with angr

### Installation

```bash
pip install angr
```

### Solution Script

```python
#!/usr/bin/env python3
import angr

# Target and avoid addresses
PRINT_FLAG = 0x08048596  # We want to reach here
NO_FLAG = 0x08048609     # We want to avoid this

print("[*] Loading binary...")
proj = angr.Project('./angr-y_binary', auto_load_libs=False)

print("[*] Setting up initial state...")
state = proj.factory.entry_state()

print("[*] Creating simulation manager...")
simgr = proj.factory.simulation_manager(state)

print("[*] Exploring paths to print_flag...")
print(f"[*] Target: 0x{PRINT_FLAG:x}")
print(f"[*] Avoid: 0x{NO_FLAG:x}")

# Explore: find print_flag, avoid no_flag
simgr.explore(find=PRINT_FLAG, avoid=NO_FLAG)

if simgr.found:
    print(f"[+] Found {len(simgr.found)} solution(s)!")
    solution = simgr.found[0]

    # Extract stdin input
    stdin_data = solution.posix.dumps(0)
    print(f"[+] Input: {stdin_data}")
    print(f"[+] Input (decoded): {stdin_data.decode('latin-1')}")
else:
    print("[-] No solution found")
```

### Execution

```bash
$ python3 solve.py
[*] Loading binary...
[*] Setting up initial state...
[*] Creating simulation manager...
[*] Exploring paths to print_flag...
[*] Target: 0x8048596
[*] Avoid: 0x8048609
[+] Found 1 solution(s)!
[*] Extracting input...
[+] Input: b'wgIdWOS6Df9sCzAfiK\x00\x00'
[+] Input (decoded): wgIdWOS6Df9sCzAfiK
```

**Password found: `wgIdWOS6Df9sCzAfiK`**

---

## Verification

### Local Test

```bash
$ echo "test_flag" > flag.txt
$ echo "wgIdWOS6Df9sCzAfiK" | ./angr-y_binary
Enter a valid password:
test_flag
```

### Remote Server

```bash
$ echo "wgIdWOS6Df9sCzAfiK" | nc 6feef76ed083a9b2.247ctf.com 50178
Enter a valid password:
247CTF{a3bbb9d2XXXXXXXXXXXXXXXX35a92945}
```

---

## Flag

```
247CTF{a3bbb9d2XXXXXXXXXXXXXXXX35a92945}
```

---

## Files in Directory

```
/root/ctf/angr_binary/
├── 5dc41cb24b73f43a4da0d2190663546159e18d5b.zip  # Original file
├── angr-y_binary                                   # Challenge binary
├── angry_revers.md                                 # This writeup
├── flag.txt                                        # Local test flag
└── solve.py                                        # Solution script
```

---

## Key Takeaways

### What is angr?

**angr** is a binary analysis framework that enables:
- **Symbolic execution**: Run the program with symbolic values instead of concrete ones
- **Path exploration**: Find paths that lead to specific states
- **Constraint solving**: Solve the conditions necessary to reach a state

### How does the solution work?

1. **Binary loading**: angr parses the ELF and creates a project
2. **Initial state**: A state is created from the entry point with symbolic stdin
3. **Simulation Manager**: Manages multiple active states during exploration
4. **Exploration**:
   - `find`: Target address(es) to reach
   - `avoid`: Address(es) to avoid (prunes the search tree)
5. **Extraction**: Once a valid state is found, symbolic values are concretized

### Why does it work?

- The binary has ~6MB of code with thousands of branches
- Each branch depends on a character of the input
- angr symbolically explores all possibilities
- By marking `no_flag` as "avoid", angr prunes incorrect paths
- The SAT/SMT solver (Z3) finds the input that satisfies the conditions

---

## Alternative Techniques

1. **Instrumentation with PIN/DynamoRIO**: Count instructions to guide brute force
2. **Directed fuzzing**: AFL with specific targets
3. **Static analysis**: Manually reconstruct the logic (infeasible for 6MB)
4. **Taint analysis**: Follow data flow from input

For this challenge, **angr** is clearly the optimal tool given the hint in the name.

---

## References

- [angr Documentation](https://docs.angr.io/)
- [angr Examples](https://github.com/angr/angr-doc/tree/master/examples)
- [Symbolic Execution - Wikipedia](https://en.wikipedia.org/wiki/Symbolic_execution)
