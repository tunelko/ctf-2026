# inconspicuous — upCTF 2026

**Category:** MISC (Reversing)
**Flag:** `upCTF{I_w4s_!a110wed_t0_write_m4lw4r3}`

## TL;DR

ELF x86-64 with self-modifying code: reads a password, uses `strlen(password) + 0x10` as XOR key to decrypt an embedded shellcode, marks it executable with `mprotect`, and executes it. The XOR key is a single byte → brute force (256 options). The decrypted shellcode compares the password byte-by-byte and prints the flag if correct.

---

## Analysis

### Reconnaissance

```bash
$ file inconspicuous
ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ strings -n 6 inconspicuous | head -5
Enter password:
il_HZgUCk(oC=}--,kyxCh,CknuhyCq(pk(n/a   # ← encrypted data visible as ASCII
```

### main() — Program Flow

```c
printf("Enter password: ");
fgets(buf, 64, stdin);
buf[strcspn(buf, "\n")] = 0;          // strip newline

key = (uint8_t)(strlen(buf) + 0x10);  // XOR key = length + 16

mem = mmap(NULL, enc_len, RW, PRIVATE|ANON, -1, 0);
for (i = 0; i < enc_len; i++)
    mem[i] = encrypted_bin[i] ^ key;  // single-byte XOR decrypt

mprotect(mem, enc_len, RX);           // mark executable
((void(*)(char*))mem)(buf);           // call decrypted shellcode
```

- `encrypted_bin`: 308 bytes in `.data` (VA `0x403060`)
- `encrypted_bin_len`: 308 (VA `0x403194`)

### XOR Key Brute Force

With 256 possible keys, we look for the one that produces a valid x86-64 prolog (`55 48 89 e5` = `push rbp; mov rbp,rsp`):

```
Key 0x1C → 55 48 89 e5 ... ✓ (valid x86-64 function)
Password length = 0x1C - 0x10 = 12
```

### Decrypted Shellcode

12 sequential password comparisons:

```nasm
mov    rax,[rbp-0x8]    ; load password pointer
movzx  eax,BYTE [rax]   ; load char
cmp    al,0x73           ; 's'
jne    fail
; ... (repeat for each char)
; input[0]='s', [1]='3', [2]='l', [3]='f', [4]='_', [5]='m'
; [6]='0', [7]='d', [8]='_', [9]='b', [10]='1', [11]='n'
; input[12] must be 0 (null terminator)
```

If the password is correct, it prints the flag via syscall:

```nasm
mov    rax,1             ; sys_write
mov    rdi,1             ; fd=stdout
lea    rsi,[rip+0xa]     ; → "upCTF{I_w4s_!a110wed_t0_write_m4lw4r3}\n"
mov    rdx,0x27          ; 39 bytes
syscall
ret
```

**Password:** `s3lf_m0d_b1n` ("self mod bin")

---

## Vulnerability

**CWE-798: Use of Hard-Coded Credentials** + **CWE-327: Use of a Broken Cryptographic Algorithm** — single-byte XOR with key derived from input length. 256 possibilities = trivial brute force.

---

## Exploit

### solve.py

```python
#!/usr/bin/env python3
import struct

elf = open("inconspicuous", "rb").read()
enc_len = struct.unpack('<I', elf[0x2194:0x2198])[0]
encrypted = elf[0x2060:0x2060 + enc_len]

for key in range(256):
    dec = bytes([b ^ key for b in encrypted])
    if dec[:4] == b'\x55\x48\x89\xe5':
        # Extract password from CMP AL,imm8 instructions
        pw = []
        i = 0
        while i < len(dec) - 1:
            if dec[i] == 0x3C:
                pw.append(chr(dec[i + 1]))
                i += 2
            else:
                i += 1
            if len(pw) == key - 0x10:
                break
        print(f"Password: {''.join(pw)}")
        # Flag embedded at offset 0x10A, length 0x27
        print(f"FLAG: {dec[0x10A:0x10A + 0x27].decode()}")
        break
```

```bash
$ python3 solve.py
Password: s3lf_m0d_b1n
FLAG: upCTF{I_w4s_!a110wed_t0_write_m4lw4r3}
```

---

## Key Lessons

1. **Self-modifying code (SMC)**: classic malware pattern — XOR decrypt → mprotect RWX → call. `mprotect` + `mmap` in imports is an immediate signal
2. **Single-byte XOR = no security**: 256 keys × x86-64 prolog validation = instant solution
3. **Key derived from length**: even without brute force, the key depends only on `strlen`, not on the password content — the full password is validated in the decrypted code, not in the key
4. **Flag embedded in shellcode**: the shellcode uses a direct `write(2)` syscall, bypassing libc — a common anti-hooking technique in real malware

## References

- [Self-modifying code — Wikipedia](https://en.wikipedia.org/wiki/Self-modifying_code)
- [mprotect(2) — Linux man page](https://man7.org/linux/man-pages/man2/mprotect.2.html)
