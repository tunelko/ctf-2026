# Nanom-dinam???itee? — Writeup

**CTF:** 0xFun CTF 2026
**Category:** Reversing
**Points:** 50
**Difficulty:** Beginner
**Author:** call4pwn
**Flag:** `0xfun{unr3adabl3_c0d3_is_s3cur3_c0d3_XD}`

> *"Don't trust what you see, trust what happens when no one is looking."*

---

## Summary

A stripped ELF binary that presents a **fake flag** visible in strings. The real verification occurs through a `fork()` + `ptrace()` scheme: the child process computes a modified FNV-1a hash for each input character and triggers a `ud2` instruction (SIGILL) after each computation. The parent process intercepts each signal, reads the hash from the child's registers and compares it against 40 hardcoded values. The flag is recovered by brute-forcing character by character.

---

## Reconnaissance

```
$ file nanom-dinam-ite__iteee
ELF 64-bit LSB pie executable, x86-64, stripped

$ strings nanom-dinam-ite__iteee | grep -i flag
Oh sure, here is your flag: 0xfun{1_10v3_M1LF}

$ ./nanom-dinam-ite__iteee
Pass: test
Oh sure, here is your flag: 0xfun{1_10v3_M1LF}
```

The flag `0xfun{1_10v3_M1LF}` is **fake** -- the hint warns about it: *"Don't trust what you see"*.

Suspicious imports:

```
fgets, puts, write, strlen, strcspn, memset  -- I/O and strings
fork, waitpid, ptrace, raise                 -- process control
exit, __stack_chk_fail                       -- flow and protection
```

The combination of `fork` + `ptrace` + `raise` indicates a parent-child debugging scheme.

---

## Static Analysis

### main (0x16cd)

```nasm
main:
    call    fork
    mov     [rbp-4], eax          ; pid = fork()
    cmp     dword [rbp-4], 0
    jne     parent_path
    call    child_func            ; pid == 0 -> child
    jmp     end
parent_path:
    mov     edi, eax
    call    parent_func           ; pid != 0 -> parent(child_pid)
end:
    mov     eax, 0
    leave
    ret
```

Two completely different execution paths:
- **Child** (pid=0) -> `child_func` @ 0x131B
- **Parent** (pid>0) -> `parent_func(child_pid)` @ 0x14AD

---

### child_func (0x131B) — The Child Process

#### Anti-debug

```nasm
    mov     edi, 0                ; PTRACE_TRACEME
    mov     esi, 0
    mov     edx, 0
    mov     ecx, 0
    call    ptrace                ; ptrace(TRACEME, 0, 0, 0)
    test    rax, rax
    jns     continue
    mov     edi, 1
    call    exit                  ; if it fails -> exit(1)
continue:
    mov     edi, 0x13             ; SIGSTOP = 19
    call    raise                 ; stop so the parent can trace
```

The child requests to be traced (`PTRACE_TRACEME`) and stops with `raise(SIGSTOP)`. If a debugger is already attached (e.g., GDB), `ptrace` fails and the binary exits.

#### Input Reading

```nasm
    ; write(1, "Pass: ", 6)
    ; fgets(buf, 0x64, stdin)
    ; strcspn(buf, "\n") -> strip newline
    ; strlen(buf)
    cmp     rax, 0x28             ; length == 40?
    je      hash_loop
    ; If not: puts("Oh sure, here is your flag: 0xfun{1_10v3_M1LF}")
    ; exit(0x63)
```

**Key point**: if the length is not exactly 40, it prints the fake flag and exits. This explains why `echo test | ./binary` shows the fake flag -- the input "test" is 4 characters, not 40.

#### Hashing Loop + ud2

```nasm
    movabs  rax, 0xcbf29ce484222325   ; FNV-1a offset basis (64-bit)
    mov     [rbp-0x90], rax            ; hash = FNV_OFFSET_BASIS

hash_loop:                             ; for i = 0 to 39:
    lea     rcx, [buf + i]             ;   &buf[i]
    mov     rdx, [rbp-0x90]            ;   hash (passed as 3rd arg)
    mov     esi, 1                     ;   length = 1
    mov     rdi, rcx                   ;   data = &buf[i]
    call    fnv_hash                   ;   hash = fnv_hash(&buf[i], 1, hash)
    mov     [rbp-0x90], rax            ;   save new hash

    mov     rcx, [loop_counter]
    mov     rax, [rbp-0x90]            ;   rax = hash
    mov     rbx, rcx                   ;   rbx = i (index)
    ud2                                ;   <- TRIGGER SIGILL (signal 4)

    add     [loop_counter], 1          ;   i++ (only executes if parent advances RIP)
    cmp     [loop_counter], 0x27
    jle     hash_loop
```

The `ud2` (**Undefined Instruction**) instruction generates SIGILL (signal 4). Since the child is being traced by the parent, the signal is intercepted by the parent instead of killing the process.

Before `ud2`, the child places in registers:
- **rax** = computed hash
- **rbx** = character index (0-39)

---

### fnv_hash (0x12A9) — Modified FNV-1a Hash

```nasm
fnv_hash:                              ; args: rdi=data, rsi=length, rdx=initial_hash
    mov     [rbp-0x10], rdx            ; hash = initial_hash
    mov     [rbp-0x8], 0              ; i = 0

loop:
    movzx   eax, byte [rdi + i]       ; byte = data[i]
    xor     [rbp-0x10], rax           ; hash ^= byte
    mov     rax, [rbp-0x10]
    movabs  rdx, 0x100000001b3        ; FNV-1a prime (64-bit)
    imul    rax, rdx                   ; hash *= FNV_PRIME
    mov     [rbp-0x10], rax
    shr     rax, 0x20                  ; temp = hash >> 32
    xor     [rbp-0x10], rax           ; hash ^= temp (<- non-standard extension)
    add     [rbp-0x8], 1              ; i++
    cmp     i, length
    jb      loop

    mov     rax, [rbp-0x10]           ; return hash
    ret
```

This is 64-bit FNV-1a with a modification: after the multiplication, `hash ^= (hash >> 32)` is applied. This mixes the high bits with the low bits, making the hash analytically non-invertible. But since it is applied character by character, brute force is trivial.

**Equivalent pseudocode:**

```python
FNV_OFFSET_BASIS = 0xcbf29ce484222325
FNV_PRIME = 0x100000001b3

def fnv_step(prev_hash, char):
    h = prev_hash ^ char
    h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    h ^= (h >> 32)
    return h
```

---

### parent_func (0x14AD) — The Parent Process

```nasm
parent_func:                           ; arg: edi = child_pid
    ; Copy 40 qwords (expected hashes) from 0x20a0 to local stack
    lea     rax, [rbp-0x150]           ; destination: local array
    lea     rdx, [rip+0xbc1]          ; source: offset 0x20a0
    mov     ecx, 0x28                  ; 40 qwords
    rep movsq                          ; memcpy

    waitpid(child_pid, &status, 0)

main_loop:                             ; while (status & 0xFF) == 0x7F (WIFSTOPPED)
    mov     eax, [status]
    and     eax, 0xFF00
    cmp     eax, 0x400                 ; signal == 4 (SIGILL)?
    jne     forward_signal

    ; === SIGILL handler ===
    ptrace(PTRACE_GETREGS, child, 0, &regs)  ; read child registers

    mov     rax, [regs.rax]            ; hash computed by child
    mov     eax, [regs.rbx]            ; character index

    ; Validate index 0 <= idx <= 39
    cmp     eax, 0
    js      kill_child
    cmp     eax, 0x27
    jg      kill_child

    ; Compare hash with expected value
    mov     rax, expected[idx]
    cmp     [saved_hash], rax
    je      advance_child
    ; If mismatch -> kill child, exit(1)

advance_child:
    add     [regs.rip], 2              ; skip ud2 (2 bytes)
    ptrace(PTRACE_SETREGS, child, 0, &regs)
    ptrace(PTRACE_CONT, child, 0, 0)  ; continue child
    waitpid(child_pid, &status, 0)
    jmp     main_loop

forward_signal:
    ; Other signal -> forward to child and continue
    ptrace(PTRACE_CONT, child, signal, 0)
    waitpid(child_pid, &status, 0)
    jmp     main_loop
```

The parent maintains a **table of 40 expected hashes** and verifies each one when the child stops with SIGILL. If the hash doesn't match, it kills the child and terminates. If it matches, it advances the child's RIP by 2 bytes (`ud2` size) so it continues with the next character.

---

## Expected Hash Table

40 64-bit values extracted from binary offset 0x20a0:

| Idx | Expected Hash | Char | Idx | Expected Hash | Char |
|-----|---------------|------|-----|---------------|------|
| 0 | `0xaf63ad4c296231e3` | `0` | 20 | `0xf344679a3a927dd0` | `3` |
| 1 | `0x6891136a394b590b` | `x` | 21 | `0xefb99a116952c3ec` | `_` |
| 2 | `0xf9dd6a7fa2d59e48` | `f` | 22 | `0xab2450955c866a6a` | `c` |
| 3 | `0x68da33e1d821d246` | `u` | 23 | `0x551f06cc6d794eb7` | `0` |
| 4 | `0x4c9850c20de0493a` | `n` | 24 | `0x1d07755e18266166` | `d` |
| 5 | `0x071a7abd930603ce` | `{` | 25 | `0x7a0d83e3733b754c` | `3` |
| 6 | `0x18024b20cb3a1de1` | `u` | 26 | `0xa06c9a7c6e643cb1` | `_` |
| 7 | `0x060337b955c30e44` | `n` | 27 | `0xfcc7536f68940bb9` | `X` |
| 8 | `0xfa85e5ec40f4c02e` | `r` | 28 | `0x1abe924ea92e99ea` | `D` |
| 9 | `0xa645cd72f9a7bc35` | `3` | 29 | `0xa06c33a9da42cee1` | `}` |
| 10 | `0x30586e5e085d6ce2` | `a` | 30 | `0xdaaa9b9d052ff54b` | -- |
| 11 | `0x83b00fc8b50f687a` | `d` | 31 | `0xbfdb7fcf6fa60f33` | -- |
| 12 | `0xd392ed0b7abf08ea` | `a` | 32 | `0xa8097d7a1f25798a` | -- |
| 13 | `0x41b15281d32a2d99` | `b` | 33 | `0xad99f0824134278c` | -- |
| 14 | `0xca7d27991ad130d6` | `l` | 34 | `0x30bb9554fb245a6c` | -- |
| 15 | `0xe3db2e2872ad3b37` | `3` | 35 | `0xf3191e664ddc910b` | -- |
| 16 | `0xdaaad6ba06f12702` | `_` | 36 | `0xf03ffbd6bdf50a6a` | -- |
| 17 | `0x81723f194ab7d6ca` | `c` | 37 | `0x31c31fe4f6a34d12` | -- |
| 18 | `0xacf831f95a9a7b37` | `0` | 38 | `0x31dc880f26a0e12d` | -- |
| 19 | `0x84383db47047b3bd` | `d` | 39 | `0x5a9c81bef9c25b4e` | -- |

*(Hashes 30-39 correspond to post-flag padding that does not affect the result)*

---

## Exploit / Solver

The hash is cumulative but applied character by character: each hash depends only on the previous hash and the current character. With only 95 printable ASCII characters per position, brute force is instantaneous.

```python
#!/usr/bin/env python3
"""
Solver for Nanom-dinam???itee?
Character-by-character brute force against modified FNV-1a hashes.
"""
import struct

FNV_OFFSET_BASIS = 0xcbf29ce484222325
FNV_PRIME        = 0x100000001b3
MASK64           = 0xFFFFFFFFFFFFFFFF

def fnv_step(prev_hash, byte_val):
    """One step of the modified FNV-1a hash (with 32-bit fold)"""
    h = prev_hash ^ byte_val
    h = (h * FNV_PRIME) & MASK64
    h ^= (h >> 32)
    return h & MASK64

# Extract 40 hashes from binary
with open('nanom-dinam-ite__iteee', 'rb') as f:
    f.seek(0x20a0)
    expected = struct.unpack('<40Q', f.read(320))

# Brute force
current_hash = FNV_OFFSET_BASIS
flag = ""

for i in range(40):
    for c in range(0x20, 0x7f):
        if fnv_step(current_hash, c) == expected[i]:
            flag += chr(c)
            current_hash = expected[i]
            break
    else:
        print(f"[-] No match at position {i}")
        break

print(f"[+] Flag: {flag}")
```

```
$ python3 solve.py
[+] Flag: 0xfun{unr3adabl3_c0d3_is_s3cur3_c0d3_XD}
```

### Verification

```
$ echo -n '0xfun{unr3adabl3_c0d3_is_s3cur3_c0d3_XD}' | ./nanom-dinam-ite__iteee
Pass:
[+] Oh oh sorry, now really this is the flag.
```

---

## Flow Diagram

```
                    +----------+
                    |  main()  |
                    |  fork()  |
                    +----+-----+
                         |
              +----------+----------+
              |                     |
         pid == 0              pid > 0
         (CHILD)               (PARENT)
              |                     |
              v                     v
    ptrace(TRACEME)         waitpid(child)
    raise(SIGSTOP)          <---------------+
              |                     |       |
              v                     v       |
    write("Pass: ")         status == SIGILL?
    fgets(buf, 100)              |          |
    len(buf) != 40? --> fake flag + exit    |
              |                  |          |
              v               Yes v         |
    hash = FNV_BASIS    GETREGS(child)      |
              |          rax = hash         |
    +-> hash = fnv(     rbx = index         |
    |    hash, buf[i])       |              |
    |         |         hash == expected[i]?|
    |         v              |              |
    |       rax = hash    Yes v        No v |
    |       rbx = i     RIP += 2      KILL  |
    |       ud2 --SIGILL--> SETREGS    EXIT |
    |         |             CONT -----------+
    |         |              |
    |    i++ (RIP advanced)  |
    |         |              |
    +--- i <= 39             |
              |              |
              v              |
    puts("[+] Oh oh sorry,   |
     now really this is      |
     the flag.")             |
    exit(0)                  |
```

---

## Key Concepts

### 1. Fake Flag as Decoy
The binary prints `0xfun{1_10v3_M1LF}` if the input doesn't have 40 characters. This traps anyone who only runs `strings` or executes it without further thought. The hint warns: *"Don't trust what you see"*.

### 2. fork() + ptrace(): Parent-Child Debugging
The child becomes a tracee (`PTRACE_TRACEME`) and the parent becomes a tracer. This serves a dual purpose:
- **Anti-debug**: only one process can trace another. If GDB is already tracing the child, `ptrace(TRACEME)` fails -> `exit(1)`.
- **Hidden verification**: the comparison logic lives in the parent, invisible if only the child's flow is analyzed.

### 3. ud2 as Communication Mechanism
`ud2` (opcode `0F 0B`, 2 bytes) is an x86 instruction that always generates SIGILL. Here it is used intentionally as a "trap point" for the parent to read the child's registers. The parent advances RIP by 2 bytes to skip the instruction and continue normal execution.

### 4. Modified FNV-1a Hash
The base hash is 64-bit FNV-1a (offset basis `0xcbf29ce484222325`, prime `0x100000001b3`) with an additional fold `hash ^= (hash >> 32)` after each multiplication. Being cumulative and applied byte by byte, it allows brute force in O(40 x 95) = O(3800) operations -- instantaneous.

---

## Flag

```
0xfun{unr3adabl3_c0d3_is_s3cur3_c0d3_XD}
```

---

## Tools Used

- **objdump**: static disassembly (Intel syntax)
- **Python 3**: hash extraction and brute force solver
- **strings**: initial reconnaissance (fake flag)
