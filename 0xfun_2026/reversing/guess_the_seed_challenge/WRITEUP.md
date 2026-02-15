# Guess The Seed — Reversing (50 pts)

**CTF:** 0xFun CTF 2026
**Category:** Reversing
**Difficulty:** Beginner
**Author:** Rick
**Flag:** `0xfun{W3l1_7h4t_w4S_Fun_4235328752619125}`

---

## Description

> I've created the ultimate number guessing game! Nobody can guess my completely unpredictable numbers. If you can somehow beat these mathematical odds and guess all 5 numbers correctly, I'll give you the flag.

## Analysis

Stripped x86-64 ELF binary. When disassembling, the flow is identified:

```asm
call   time@plt        ; time(0)
mov    edi, eax
call   srand@plt       ; srand(time(NULL))
call   rand@plt        ; -> r12d
call   rand@plt        ; -> r15d
call   rand@plt        ; -> r14d
call   rand@plt        ; -> ebp
call   rand@plt        ; -> ebx
```

Then applies `% 1000` to each value (compiler-optimized as `imul rax, reg, 0x10624dd3` + shifts), reads 5 integers via `scanf`, and compares them one by one.

**Summary**: `srand(time(NULL))` -> 5x `rand() % 1000` -> compare with user input.

## Exploit

Synchronize the seed by computing `rand() % 1000` with the same timestamp:

```python
import ctypes, time, subprocess

libc = ctypes.CDLL('libc.so.6')

# Prepare for the next second
t_target = int(time.time()) + 1
libc.srand(t_target)
nums = [libc.rand() % 1000 for _ in range(5)]
answer = ' '.join(map(str, nums))

# Wait for the exact second
while int(time.time()) < t_target:
    time.sleep(0.01)

# Execute synchronized
proc = subprocess.Popen(['./guess_the_seed'],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE)
stdout, _ = proc.communicate(input=answer.encode() + b'\n')
print(stdout.decode())
```

The key is to pre-compute the values for `t+1` and launch the binary right when the clock changes to that second.
