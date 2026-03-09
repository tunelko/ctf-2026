# jumpy

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | UNbreakable 2026               |
| Category    | rev                            |
| Difficulty  | Hard                           |
| Points      | -                              |

## Description

> Custom cipher binary. Find the flag encrypted in `enc.sky`.

## TL;DR

Stripped binary implements `UNBR26::GrayInterleaveSbox::v1` — a custom block cipher with self-modifying code. 14 code blocks are XOR-encrypted in the binary and decrypted at runtime as a state machine. The cipher processes 32-byte blocks in byte pairs: XOR round key → nonlinear mix → Gray code → nibble interleave → S-box → bit rotation. All operations are invertible. Decrypting `enc.sky` produces the flag.

## Initial analysis

### Provided files

```
dist/chall      ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
dist/enc.sky    96 bytes of encrypted data
```

### Reconnaissance

```bash
$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
       interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped

$ pwn checksec chall
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

$ wc -c enc.sky
96 enc.sky

$ xxd enc.sky
00000000: d6e0 d3f8 2b43 e50c b103 ff13 3f9d b271  ....+C......?..q
00000010: fbc6 6888 fa11 024b f7d2 648e 6d0f cfa0  ..h....K..d.m...
00000020: 1692 fc88 715a 7c4f cfd1 3318 5e9f a569  ....qZ|O..3.^..i
00000030: a3e3 7c4e 5f28 78cf c1c1 95c6 84b7 689a  ..|N_(x.......h.
00000040: 1b0e 4965 11e6 24f5 3e6c c9f2 e03a 7d11  ..Ie..$.>l...:}.
00000050: 5f62 c455 b6ba a47a c2ae 441b d547 9abc  _b.U...z..D..G..
```

96 bytes = 3 blocks of 32 bytes.

### Imported functions

```bash
$ r2 -q -e scr.color=0 -c 'aaa; afl' chall
0x00401120    sym.imp.write
0x00401130    sym.imp.memset
0x00401140    sym.imp.dprintf
0x00401150    sym.imp.SHA256_Init
0x00401160    sym.imp.open
0x00401170    sym.imp.memcpy
0x00401180    sym.imp.__stack_chk_fail
0x00401190    sym.imp.getenv
0x004011a0    sym.imp.read
0x004011b0    sym.imp.mprotect
0x004011c0    sym.imp._exit
0x004011d0    sym.imp.SHA256_Update
0x004011e0    sym.imp.mmap
0x004011f0    sym.imp.close
0x00401200    sym.imp.SHA256_Final
0x004012f6   74 5790 -> 3879 fcn.004012f6    ; main function
```

A single main function of 3879 bytes. Uses SHA256 for key derivation, `mprotect` to make code writable, `mmap` for working memory, and `getenv` (possible debug mode).

### ELF sections

```bash
$ readelf -S chall | grep -E 'rodata|text|data'
  [16] .text             PROGBITS    0x401210  0x1210  0x179d  AX
  [18] .rodata           PROGBITS    0x403000  0x3000  0x00a0  A
  [26] .data             PROGBITS    0x405078  0x4078  0x0010  WA
```

No PIE → fixed addresses. `.rodata` contains strings and encrypted cipher data.

## Solution process

### Step 1: Decompilation with Ghidra headless

```bash
$ cat decompile.py
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
decomp = DecompInterface()
decomp.openProgram(currentProgram)
fm = currentProgram.getFunctionManager()
for f in fm.getFunctions(True):
    addr = f.getEntryPoint().getOffset()
    if addr >= 0x401200 and addr <= 0x402a00:
        res = decomp.decompileFunction(f, 120, ConsoleTaskMonitor())
        if res.decompileCompleted():
            print(res.getDecompiledFunction().getC())

$ /usr/share/ghidra/support/analyzeHeadless . ghidra_proj -import chall -postScript decompile.py
```

Relevant output (simplified):

```c
void FUN_004012f6(void) {
    // 1. mmap(0x133700, 0x1000, RW) — working memory
    local_580 = mmap((void *)0x133700, 0x1000, 3, 0x32, -1, 0);

    // 2. read(0, buf, 0x100) — read user input
    uVar3 = read(0, local_580, 0x100);

    // 3. XOR decode cipher name from 0x403060 (30 bytes, key=0xa5)
    for (i = 0; i < 0x1e; i++)
        local_318[i] = DAT_00403060[i] ^ 0xa5;

    // 4. XOR key1 (0x403080) with key2 (0x403090) → 16-byte secret
    for (i = 0; i < 0x10; i++)
        local_328[i] = DAT_00403080[i] ^ DAT_00403090[i];

    // 5. PKCS padding to 32-byte blocks
    pad = 0x20 - (uint)uVar3 % 0x20;
    memcpy(dest, local_580, uVar3);
    memset(dest + uVar3, pad, pad);

    // 6. SHA256(cipher_name || secret) → 32-byte key
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, local_318, 0x1e);
    SHA256_Update(&ctx, local_328, 0x10);
    SHA256_Final(sha256_key, &ctx);

    // 7. Fisher-Yates shuffle → build S-box (256 bytes)
    // 8. Build inverse S-box
    // 9. FNV-1a hashes for state initialization
    // 10. mprotect(.text, RWX) — enable self-modifying code
    // 11. Per-block encryption loop (state machine)
    // 12. Write result to "enc.sky"

    // Debug mode: if getenv("X") → print block layout and exit
}
```

### Step 2: Extracting data from .rodata

```bash
$ python3 -c "
with open('chall', 'rb') as f:
    f.seek(0x3000)
    rodata = f.read(0xa0)

# Cipher name (0x403060, 30 bytes, XOR 0xa5)
cipher_enc = rodata[0x60:0x60+0x1e]
cipher_name = bytes(b ^ 0xa5 for b in cipher_enc)
print(f'Cipher name: {cipher_name}')

# Keys
key1 = rodata[0x80:0x80+0x10]
key2 = rodata[0x90:0x90+0x10]
xored = bytes(a ^ b for a, b in zip(key1, key2))
print(f'key1 ^ key2 = {xored.hex()}')
"
```

Output:
```
Cipher name: b'UNBR26::GrayInterleaveSbox::v1'
key1 ^ key2 = 1337c0de26aabbccdeadbeef42241999
```

XORing the two keys yields a recognizable value (`0x1337c0de...`). It is a hardcoded constant.

### Step 3: Debug mode — block layout

```bash
$ chmod +x chall
$ echo "AAAA" | X=1 ./chall
# block_id  vaddr  size
0  0x401fd3  182
1  0x402089  85
2  0x4020de  69
3  0x402123  103
4  0x40218a  109
5  0x4021f7  30
6  0x402215  121
7  0x40228e  83
8  0x4022e1  271
9  0x4023f0  163
10  0x402493  186
11  0x40254d  251
12  0x402648  107
13  0x4026b3  152
NOP  0x401bda  232
```

The environment variable `X` (detected by `getenv("X")`) activates a debug mode that displays the addresses and sizes of the 14 encrypted code blocks, plus a NOP padding block.

### Step 4: Static decryption of code blocks

From the dispatcher disassembly at `0x401e18`, each block is encrypted/decrypted with byte-by-byte XOR:

```
key_byte[i] = (37 * block_id + 13 * offset) ^ 0xCB
```

Script to decrypt all blocks:

```python
blocks = [
    (0, 0x401fd3, 182), (1, 0x402089, 85),  (2, 0x4020de, 69),
    (3, 0x402123, 103), (4, 0x40218a, 109), (5, 0x4021f7, 30),
    (6, 0x402215, 121), (7, 0x40228e, 83),  (8, 0x4022e1, 271),
    (9, 0x4023f0, 163), (10, 0x402493, 186), (11, 0x40254d, 251),
    (12, 0x402648, 107), (13, 0x4026b3, 152),
]

with open('chall', 'rb') as f:
    binary = bytearray(f.read())

for block_id, vaddr, size in blocks:
    file_off = vaddr - 0x401210 + 0x1210
    decrypted = bytearray(size)
    for i in range(size):
        key_byte = ((37 * block_id + 13 * i) ^ 0xcb) & 0xff
        decrypted[i] = binary[file_off + i] ^ key_byte
    print(disasm(bytes(decrypted), vma=vaddr))
```

Example output — Block 0 (Nibble interleave):
```asm
401fd3: endbr64
401fd7: movzx  eax, BYTE PTR [rbp-0x626]    ; byte_a
401fde: shr    al, 0x4                        ; a_hi
401fe1: mov    BYTE PTR [rbp-0x622], al
401fe7: movzx  eax, BYTE PTR [rbp-0x626]
401fee: and    eax, 0xf                        ; a_lo
...
402021: shl    eax, 0x4
402023: mov    edx, eax
40202a: or     eax, edx                        ; a = (a_hi << 4) | b_lo
40202c: mov    BYTE PTR [rbp-0x626], al
...
```

Example — Block 12 (S-box substitution):
```asm
40266e: movzx  eax, BYTE PTR [rbp-0x626]     ; byte_a
402675: cdqe
402677: movzx  eax, BYTE PTR [rbp+rax*1-0x210] ; sbox[byte_a]
40267f: mov    BYTE PTR [rbp-0x626], al
```

### Step 5: Diffusion analysis

To confirm pair-wise processing, we test by flipping individual input bits:

```bash
$ python3 -c "
# Test: encrypt zeros, then flip one input bit at a time
# Check which output bits change
base = encrypt(b'\x00' * 64)
for byte_pos in range(32):
    for bit in range(8):
        inp = bytearray(64)
        inp[byte_pos] = 1 << bit
        ct = encrypt(bytes(inp))
        diffs = [i for i in range(32) if ct[i] != base[i]]
        print(f'in[{byte_pos}] bit {bit} -> out bytes: {diffs}')
"
```

Result: input bytes `[0,1]` only affect output bytes `[0,1]`. Input bytes `[2,3]` only affect `[2,3]`. **Diffusion is limited to 2-byte pairs.**

### Step 6: Verification with Unicorn Engine

To confirm the exact sequence of operations, the state machine was emulated with Unicorn:

```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)
# Map binary, stack, mmap regions
mu.mem_map(0x400000, 0x6000, UC_PROT_ALL)
mu.mem_write(0x400000, binary[:0x4088])
# ... setup stack, decrypt all blocks in memory,
# ... write S-box, round keys, permutation tables

# NOP out the self-modify XOR loops (already decrypted statically)
mu.mem_write(0x401ecb, b'\x90\x90')  # re-encrypt write
mu.mem_write(0x401fa5, b'\x90\x90')  # decrypt write

# Emulate block by block, trace which blocks execute
for iteration in range(max_blocks):
    next_block = read_var(RBP - 0x5b4)
    if next_block < 0: break
    block_trace.append(next_block)
    mu.emu_start(block_addrs[next_block], 0x401e18)
```

Output:
```
Emulated block 0: 5f3f2cf27d3eb3331c7b754919432d190a728730255596390ff552743b512b33
Real block 0:     5f3f2cf27d3eb3331c7b754919432d190a728730255596390ff552743b512b33
Match: True
Block trace: [2, 4, 5, 10, 5, 8, 5, 9, 5, 10, 5, 8, 5, 9, 0, 5, 12, 5, 11, 5, 12, 5, 11, 1, 3, ...]
```

Perfect match. The trace reveals the sequence (removing block 5 which is a dispatcher):

```
Per byte pair: 4(load) → 10(XOR key_a) → 8(nonlinear_a) → 9(gray_a) →
               10(XOR key_b) → 8(nonlinear_b) → 9(gray_b) →
               0(nibble interleave) →
               12(sbox_a) → 11(rotate_a) → 12(sbox_b) → 11(rotate_b) →
               1(store) → 3(advance counter)
```

### Step 7: Manual step-by-step verification

```python
# Block 0, counter=0, byte_a=0x00, byte_b=0x00
round_key = SHA256(sha256_key || "KS" || LE32(0))
# round_key[0] = 0x42, round_key[1] = 0x19

# Step 1: XOR round key
a = 0x00 ^ 0x42 = 0x42
b = 0x00 ^ 0x19 = 0x19

# Step 2: Nonlinear mix  ((a^k) + 2*(a&k) = a + k)
# k_a = (31*0 + 17*0) & 0xff = 0x00
a = 0x42 + 0x00 = 0x42
# k_b = (31*0 + 17*1) & 0xff = 0x11
b = 0x19 + 0x11 = 0x2a

# Step 3: Gray code
a = 0x42 ^ (0x42 >> 1) = 0x42 ^ 0x21 = 0x63
b = 0x2a ^ (0x2a >> 1) = 0x2a ^ 0x15 = 0x3f

# Step 4: Nibble interleave
a = (0x6_ << 4) | 0x_f = 0x6f
b = (0x3_ << 4) | 0x_3 = 0x33

# Step 5: S-box
a = sbox[0x6f] = 0xd7
b = sbox[0x33] = 0x9f

# Step 6: Rotate left
a = ROL(0xd7, 0x42 & 7) = ROL(0xd7, 2) = 0x5f
b = ROL(0x9f, 0x19 & 7) = ROL(0x9f, 1) = 0x3f

# Result: 0x5f, 0x3f ← matches real output!
```

### Step 8: Identifying the key inversion

The "nonlinear mix" operation appears complex:
```c
result = (val ^ key) + 2 * (val & key)
```

But algebraically: `(a XOR b) + 2*(a AND b) = a + b` (binary arithmetic identity).

**Proof**: for each bit `i`, `a_i XOR b_i + 2*(a_i AND b_i)` produces exactly `a_i + b_i` with carry. This extends to full bytes as modular addition.

Therefore: `inverse(result, key) = (result - key) mod 256`.

### Step 9: Implementing decrypt and extracting the flag

```python
def decrypt_block(ciphertext, block_counter):
    buf = bytearray(ciphertext)
    rk = gen_round_key(block_counter)
    for pos in range(0, 32, 2):
        a, b = buf[pos], buf[pos + 1]
        # Reverse rotation
        a = rotate_right(a, (rk[pos] + 8) & 7)
        b = rotate_right(b, (rk[pos + 1] + 8) & 7)
        # Reverse S-box
        a, b = inv_sbox[a], inv_sbox[b]
        # Reverse nibble interleave (self-inverse)
        a, b = nibble_interleave(a, b)
        # Reverse Gray code
        a, b = gray_decode(a), gray_decode(b)
        # Reverse nonlinear mix (a - k mod 256)
        a = (a - (31*block_counter + 17*pos) & 0xff) & 0xff
        b = (b - (31*block_counter + 17*(pos+1)) & 0xff) & 0xff
        # Reverse XOR
        a ^= rk[pos]; b ^= rk[pos + 1]
        buf[pos], buf[pos+1] = a, b
    return bytes(buf)
```

```bash
$ python3 solve.py
[*] Verifying encryption...
  My:   5f3f2cf27d3eb3331c7b754919432d190a728730255596390ff552743b512b33
  Real: 5f3f2cf27d3eb3331c7b754919432d190a728730255596390ff552743b512b33
  Match: True
  Decrypt roundtrip: True
  Block 1 match: True

[*] Decrypting enc.sky...
  96 bytes = 3 blocks
  Block 0: b'UNBR{daca_faci_challu_esti_magna'
  Block 1: b't_si_ai_furat_34_67_date_persona'
  Block 2: b'les_boss}\x17\x17\x17...' (23 bytes padding)

  Removed 23 bytes of padding

[+] Flag: UNBR{daca_faci_challu_esti_magnat_si_ai_furat_34_67_date_personales_boss}
```

### Step 10: Verification by re-encrypting the flag

```bash
$ echo -n 'UNBR{daca_faci_challu_esti_magnat_si_ai_furat_34_67_date_personales_boss}' | ./chall
$ diff enc.sky enc.sky.original
# (no output = identical files)
```

## Cipher structure

### Key derivation

```python
cipher_name = XOR_decode(0x403060, 0xa5)  # "UNBR26::GrayInterleaveSbox::v1" (30 bytes)
secret = 0x403080 XOR 0x403090            # 0x1337c0de26aabbccdeadbeef42241999 (16 bytes)
sha256_key = SHA256(cipher_name || secret) # 32 bytes
round_key[i] = SHA256(sha256_key || "KS" || LE32(i))  # per-block, 32 bytes
```

### S-box construction

Fisher-Yates shuffle (downward) with SHA256-based PRNG:
- Initial: `sbox = [0, 1, 2, ..., 255]`
- For `i = 255 → 1`: `j = SHA256_PRNG_byte() % (i+1)`, swap `sbox[i]`, `sbox[j]`
- PRNG: SHA256 chain from `sha256_key`, regenerated every 32 bytes

### Self-modifying code mechanism

14 code blocks in `.text` (0x401fd3-0x40274b), encrypted with XOR:

```
key[i] = (37 * block_id + 13 * byte_offset) ^ 0xCB
```

The dispatcher at `0x401e18`:
1. Re-encrypts the previous block (idempotent XOR)
2. Decrypts the next block
3. Jumps to the decrypted block
4. The block sets `var_5b4h` (next block) and jumps back to the dispatcher

### Cipher operations per byte pair

| Step | Block | Operation | Inverse |
|------|-------|-----------|---------|
| 1 | 4 | Load `a,b = buf[pos:pos+2]` | Store |
| 2 | 10 | `a ^= rk[pos]` | `a ^= rk[pos]` |
| 3 | 8 | `a += nlk_a` (mod 256) | `a -= nlk_a` (mod 256) |
| 4 | 9 | `a = gray(a)` | `a = inv_gray(a)` |
| 5 | 10 | `b ^= rk[pos+1]` | `b ^= rk[pos+1]` |
| 6 | 8 | `b += nlk_b` (mod 256) | `b -= nlk_b` (mod 256) |
| 7 | 9 | `b = gray(b)` | `b = inv_gray(b)` |
| 8 | 0 | Nibble interleave (a<->b) | Same (involution) |
| 9 | 12 | `a = sbox[a]` | `a = inv_sbox[a]` |
| 10 | 11 | `a = ROL(a, rk[pos]&7)` | `a = ROR(a, rk[pos]&7)` |
| 11 | 12 | `b = sbox[b]` | `b = inv_sbox[b]` |
| 12 | 11 | `b = ROL(b, rk[pos+1]&7)` | `b = ROR(b, rk[pos+1]&7)` |
| 13 | 1 | Store | Load |

Where `nlk_a = (31 * block_counter + 17 * pos) & 0xff` and `nlk_b = (31 * block_counter + 17 * (pos+1)) & 0xff`.

Additional blocks (6, 7, 13) update a `state_hash` variable that does NOT affect the encryption.

## Final exploit

See [`solve.py`](solve.py). Standalone script that:
1. Reproduces the key derivation
2. Builds S-box and inverse S-box
3. Verifies the implementation against the real binary
4. Decrypts the 3 blocks of `enc.sky`
5. Removes PKCS padding and displays the flag

## Execution

```bash
python3 solve.py
```

## Flag

```
UNBR{daca_faci_challu_esti_magnat_si_ai_furat_34_67_date_personales_boss}
```

## Discarded approaches

1. **Brute-force by byte pairs**: With diffusion limited to 2 bytes, 65536 combinations per pair could be tested. But it would require ~1M binary invocations → too slow. Algebraic inversion was chosen instead.
2. **GDB batch trace**: Attempted to trace block execution with GDB breakpoints, but with ~400 blocks per 32-byte block it was prohibitively slow. Unicorn emulation was much faster.

## Key Lessons

- **Self-modifying code with deterministic keys**: If the XOR key depends only on static values (`block_id`, `offset`), it can be decrypted offline without executing the binary. Look for `mprotect(RWX)` as an indicator.
- **`(a XOR b) + 2*(a AND b) = a + b`**: Crucial algebraic identity. What appears to be a complex nonlinear operation is simply modular addition, trivially invertible.
- **Unicorn for fast verification**: Emulating specific code regions validates the reverse engineering before committing to a full reimplementation.
- **`getenv` = possible debug mode**: Always check `getenv` calls — this one revealed the block layout.
- **Diffusion limited to pairs**: The absence of cross-pair diffusion would also enable brute-force as a plan B (65536 per pair x 16 pairs = ~1M), though direct inversion is preferable.
- **PKCS padding**: 96 bytes - 23 bytes padding = 73 bytes of plaintext → exact flag length.

## References

- [Unicorn Engine](https://www.unicorn-engine.org/)
- [Gray code](https://en.wikipedia.org/wiki/Gray_code)
- [Fisher-Yates shuffle](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle)
- [Binary arithmetic identity: XOR + 2*AND = ADD](https://en.wikipedia.org/wiki/Adder_(electronics)#Full_adder)
