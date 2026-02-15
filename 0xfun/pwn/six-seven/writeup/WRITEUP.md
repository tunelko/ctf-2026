# six-seven-lmao

## Challenge Info
- **Category**: Pwn (Heap Exploitation)
- **Remote**: `nc chall.0xfun.org 10582`
- **Binary**: ELF 64-bit LSB PIE, x86-64
- **Libc**: glibc 2.42
- **Flag**: `0xfun{p4cm4n_Syu_br0k3_my_xpl0it_btW}`

## Analysis

### Binary protections
```
Full RELRO    Canary found    NX enabled    PIE enabled
```

All protections enabled - no GOT overwrite, no shellcode, no fixed addresses.

### Functionality
Note management system with 10 slots (indices 0-9), max note size 0x400:
1. **Create** - `malloc(size)` + `read(0, buf, size)`
2. **Delete** - `free(notes[idx])` (UAF: doesn't NULL `notes[]` or clear `sizes[]`)
3. **Read** - `write(1, notes[idx], sizes[idx])`
4. **Edit** - `read(0, notes[idx], sizes[idx])`
5. **Exit** - calls `exit()`

### Vulnerability
**Use-After-Free (UAF)**: `delete_note` frees the chunk but leaves the pointer in `notes[]` and size in `sizes[]`. This allows reading freed chunk metadata (heap/libc leaks) and editing freed chunk fd pointers (tcache poisoning).

## Exploitation: House of Apple 2

### Step 1: Heap Leak
Allocate and free a small chunk (0x18). Read the freed chunk's tcache fd pointer. With safe-linking in glibc 2.42, the first tcache entry has `fd = pos >> 12` (next is NULL), giving us `heap_base`.

### Step 2: Libc Leak
Allocate 9 chunks of 0x400 (fills indices 0-8). Free 7 chunks (0-6) to fill the tcache. Free chunk 7 which goes to the unsorted bin (chunk 8 is guard). Read chunk 7's fd pointer to leak a libc address (`main_arena + offset`).

### Step 3: Tcache Poison
Edit freed chunk 6's fd pointer with a mangled pointer to `_IO_list_all`:
```
mangled_target = (chunk6_addr >> 12) ^ _IO_list_all
```

### Step 4: Fake FILE (House of Apple 2)
Allocate chunk6 back from tcache, filling it with a crafted fake FILE struct:

```
+0x000: _IO_FILE_plus (fake FILE struct)
+0x100: _IO_wide_data (fake wide data)
+0x200: wide_vtable   (fake wide vtable with __doallocate = system)
+0x300: _lock area     (zeroed memory = unlocked mutex)
```

Key fields:
- `_flags` = `"  sh;\0\0\0"` - argument to `system()`
- `_IO_write_base` = 0, `_IO_write_ptr` = 1 - triggers overflow condition
- `_IO_buf_base` = non-NULL - **critical**: prevents `_IO_doallocbuf` from calling `malloc()` on corrupted tcache
- `_lock` = writable zeroed address - required for glibc 2.42's file locking
- `_wide_data` → fake wide_data at +0x100
- `vtable` = `_IO_wfile_jumps`
- wide `_wide_vtable` → fake vtable at +0x200
- wide vtable `__doallocate` = `system`

### Step 5: Overwrite _IO_list_all
Next tcache allocation goes to `_IO_list_all`, write pointer to our fake FILE.

### Step 6: Trigger
Call `exit()` → `_IO_flush_all` → iterates FILE list → processes our fake FILE:
1. `_IO_flush_all` calls `__overflow(fp, EOF)` = `_IO_wfile_overflow`
2. `_IO_wfile_overflow` sees `wide_data->_IO_buf_base == NULL` → calls `_IO_wdoallocbuf`
3. `_IO_wdoallocbuf` calls `wide_vtable->__doallocate(fp)` = `system("  sh;")`
4. Shell spawned!

## Key Challenges

### glibc 2.42 tcache_perthread_struct size
The `tcache_perthread_struct` in glibc 2.42 uses a **0x300-byte chunk** (not 0x290 as in older versions). This shifts all heap allocation addresses by +0x60 compared to the standard formula. Wrong offset = completely wrong fake FILE alignment = crash.

**Correct formula**: `chunk_i_data = heap_base + 0x330 + i * 0x410`

### _IO_buf_base must be non-NULL
After `system()` returns from `_IO_wdoallocbuf`, `_IO_wfile_overflow` continues execution and calls `_IO_doallocbuf(fp)`. If `_IO_buf_base` is NULL, this triggers `malloc(BUFSIZ)` which hits the corrupted 0x410 tcache bin and crashes. Setting `_IO_buf_base` to a valid non-NULL address makes `_IO_doallocbuf` return immediately.

### _lock field required in glibc 2.42
glibc 2.42's `_IO_flush_all` **always** acquires the FILE lock (no `_IO_flush_all_lockp` bypass). The `_lock` pointer must point to valid writable zeroed memory (acts as an unlocked `pthread_mutex_t`).

## Scripts
- `exploit.py` - Main exploit (supports LOCAL/REMOTE/GDB modes)

## Usage
```bash
python3 exploit.py          # LOCAL
python3 exploit.py REMOTE   # REMOTE
python3 exploit.py GDB      # GDB debugging
```

## Key Lessons
1. **Always verify heap layout with GDB** - don't assume standard tcache struct sizes across glibc versions
2. **House of Apple 2 post-system() cleanup** - the code path continues after `system()` returns; all FILE struct fields must be consistent to avoid crashes in subsequent operations
3. **glibc 2.42 changes**: larger tcache struct (0x300 chunk), mandatory FILE locking in `_IO_flush_all`, no wide vtable validation in `_IO_wdoallocbuf`
