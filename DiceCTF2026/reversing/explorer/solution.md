# Explorer

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | DiceCTF 2026                   |
| Category    | reversing                      |
| Difficulty  | Medium                         |
| Connection  | `nc explorer.chals.dicec.tf 1337` |

## Description

> I found this riddle in some ancient language, but I'm not sure what it means...

Two files are provided: `bzImage` (Linux kernel) and `initramfs.cpio.gz` (root filesystem). Connecting to the service gives a QEMU VM that boots with this kernel.

## TL;DR

Linux kernel with a custom Rust driver at `/dev/challenge` that implements a random maze accessible via ioctl. The driver must be reversed to discover the interface, then the maze must be traversed avoiding fake goals (R5=2) until finding the real goal (R5=1) which unlocks the flag.

## Initial Analysis

### Extracting the initramfs

```bash
mkdir /tmp/initramfs && cd /tmp/initramfs
gzip -dc initramfs.cpio.gz | cpio -idmv
```

The `init` script reveals the key piece:

```bash
if [ ! -e /dev/challenge ]; then
  mknod /dev/challenge c 10 123
fi
chmod 666 /dev/challenge
exec setsid cttyhack su -s /bin/sh ctf
```

A misc device (major 10) with read/write permissions for everyone.

### Extracting the kernel

```bash
/usr/src/linux-headers-$(uname -r)/scripts/extract-vmlinux bzImage > vmlinux
```

Result: ELF 64-bit, statically linked, stripped. 12.7MB.

### Relevant strings

```
$ strings vmlinux | grep -i "challenge\|dice{"
dice{fake_flag_for_testing}
drivers/misc/challenge.rs
drivers/misc/challenge.rs:266
drivers/misc/challenge.rs:170
```

The driver is written in **Rust** (`challenge.rs`). It contains an embedded fake test flag.

## Vulnerability Identified

Not a classic vulnerability, but a **reversing + interaction** challenge. The driver exposes a random maze through ioctl and it must be solved programmatically.

### Type

Reverse engineering of a Rust kernel driver.

## Solution Process

### Step 1: Reversing the ioctl dispatch

Locating the ioctl handler function (from references to the fake flag at `0xffffffff813bdae8`), a dispatch based on the ioctl command in `ecx` is identified:

```nasm
; Extract from main dispatch
cmp ecx, 0x80046484    ; jg  → high group
cmp ecx, 0x80046481    ; jle → low group
cmp ecx, 0x80046482    ; je  → handler R2
cmp ecx, 0x80046483    ; je  → handler R3
; ... etc
```

Decoding the ioctl numbers with the `_IOC(dir, type, nr, size)` macro:

| Command      | Decoding                       | Function                           |
|-------------|------------------------------|------------------------------------|
| `0x80046480` | `_IOR('d', 0x80, u32)`       | R0: Maze seed (fixed)              |
| `0x80046481` | `_IOR('d', 0x81, u32)`       | R1: Maze width                     |
| `0x80046482` | `_IOR('d', 0x82, u32)`       | R2: Maze height                    |
| `0x80046483` | `_IOR('d', 0x83, u32)`       | R3: Maze property                  |
| `0x80046484` | `_IOR('d', 0x84, u32)`       | R4: Step counter                   |
| `0x80046485` | `_IOR('d', 0x85, u32)`       | R5: Goal flag (0/1/2)              |
| `0x80046486` | `_IOR('d', 0x86, u32)`       | R6: Free directions bitmask        |
| `0x80406487` | `_IOR('d', 0x87, [u8;64])`   | FLAG: Read flag (only if R5==1)    |
| `0x40046488` | `_IOW('d', 0x88, u32)`       | W8: Move (value 0-5)               |
| `0x00006489` | `_IO('d', 0x89)`             | ACT: Reset to start                |

All use type `'d'` (0x64, for "dice").

### Step 2: Reversing the room structure

Analyzing the move handler (`W8`) reveals the structure of each maze node:

```c
// Room structure (offsets from room base pointer)
struct Room {
    // ...
    mutex lock;               // +0x10
    // ...
    struct Room *neighbors[6]; // +0x28, +0x30, +0x38, +0x40, +0x48, +0x50
    uint8_t goal_flag;         // +0x58 (0=normal, 1=real goal, 2=decoy)
};
```

The move handler:

```nasm
; r13 = direction (0-5), rbx = current room
mov r13, [rbx + r13*8 + 0x28]   ; r13 = room->neighbors[direction]
test r13, r13
je  no_exit                       ; NULL → EAGAIN

; ... reference counting, ownership transfer ...

mov [r14+0x18], r13               ; state->current_room = new room
inc DWORD [r14+0x54]              ; state->steps++
mov al, [r13+0x58]                ; new room's goal flag
test al, al
je skip
mov [r14+0x58], al                ; state->solved = goal_flag
```

### Step 3: Reversing the FLAG handler

```nasm
cmp BYTE [r14+0x58], 1    ; R5 == 1 exactly?
jne return_EPERM           ; If not, error -1 (EPERM)

; Builds "dice{fake_flag_for_testing}" on stack (local version)
; Copies 64 bytes to user buffer
```

Critical discovery: **the flag is only delivered if R5 == 1 exactly**. Rooms with `goal_flag == 2` are decoys.

### Step 4: Reversing the R6 handler (available directions)

```nasm
; For each neighbor[i] (i=0..5):
cmp QWORD [rbp + 0x28 + i*8], 0
; If not NULL → set bit i in result
```

R6 returns a 6-bit bitmask where each bit indicates whether that direction has an accessible neighbor.

### Step 5: Determining opposite directions

Testing in the VM: from the start only direction 2 is available. Moving in direction 2, the available directions are 0 and 2. This confirms:

- **0 <-> 2** (opposites)
- **1 <-> 3** (opposites)
- **4 <-> 5** (opposites)

Formula: `opposite(d) = (d+2)%4` for d<4, `opposite(d) = d^1` for d>=4.

### Step 6: Movement restriction

The `W8` handler also checks:

```nasm
cmp BYTE [r14+0x58], 0    ; R5 == 0?
je  continue               ; Can only move if a goal has NOT been reached
```

Once a room with goal_flag != 0 is stepped on, further movement is blocked. Only `ACT` (reset) restores R5=0.

### Step 7: Developing the solver

Without a unique room identifier (R0-R3 are static maze properties), a **DFS with backtracking via path replay** is implemented:

1. `ACT` → reset to start
2. At each node, try each available direction (except the return direction)
3. If a goal with R5=2 is reached → decoy, do `ACT` + replay the path and try another direction
4. If a goal with R5=1 is reached → read FLAG with ioctl `0x87`
5. If no more directions → backtrack: `path_len--`, `ACT` + replay

Backtracking requires reconstructing the complete state from scratch (`ACT` + replay of all moves) because there is no ioctl to go back one step.

### Step 8: Compilation and upload to the VM

The solver is compiled with **musl-gcc** to obtain a minimal static binary (~17KB):

```bash
musl-gcc -static -Os -s -o solve solve.c
```

It is uploaded to the QEMU VM via the serial console:

```python
# Compress and encode
compressed = gzip.compress(binary, compresslevel=9)
b64 = base64.b64encode(compressed).decode()  # ~5KB

# Upload in 512-byte chunks
for chunk in chunks(b64, 512):
    r.sendline(f"echo -n '{chunk}' >> /tmp/b64")

# Decode and execute
r.sendline(b'base64 -d /tmp/b64 | gunzip > /tmp/s && chmod +x /tmp/s')
r.sendline(b'/tmp/s')
```

### Step 9: Execution

```
R0=1694217203 R1=10 R2=16 R3=13
nodes=100 depth=99
nodes=200 depth=199
Goal r5=2 depth=298 steps=298     ← decoy!
Goal r5=1 depth=298 steps=298     ← real goal!
FLAG ret=0
FLAG=dice{twisty_rusty_kernel_maze}
```

The DFS first finds the decoy (R5=2), discards it, and in the next branch finds the real goal (R5=1).

## Discarded Approaches

1. **Direct read/write** to the device → `EINVAL` (only supports ioctl)
2. **Using R0 as room identifier** → R0 is constant for the entire session
3. **BFS with cycle detection by R0** → impossible without room ID, BFS explodes
4. **Stopping at the first goal (R5!=0)** → R5=2 is a decoy, the flag requires R5==1
5. **Movement `opposite = d ^ 1`** → incorrect, the pairs are 0<->2, 1<->3, 4<->5

## Final Exploit

See `solve.c` — compile with:

```bash
musl-gcc -static -Os -s -o solve solve.c
```

## Execution

```bash
# Compile
musl-gcc -static -Os -s -o solve solve.c

# Upload and execute via Python script (see upload in step 8)
python3 upload_and_run.py
```

## Flag

```
dice{twisty_rusty_kernel_maze}
```

## Key Lessons

- Rust kernel drivers in CTFs use the same pattern as C: ioctl dispatch with `_IOC(dir, type, nr, size)`
- When there are no node identifiers, DFS with path replay is viable for moderate-sized mazes (~300 nodes)
- Always verify exact conditions: `R5 == 1` is not the same as `R5 != 0`. Decoys (R5=2) are a deliberate trap
- musl-gcc produces static binaries 40x smaller than glibc (~17KB vs ~700KB), critical for uploading to VMs via serial
- The name "Explorer" and "Explorer Mouse" in dmesg were hints about the nature of the challenge (maze exploration)

## References

- [Linux ioctl macros](https://elixir.bootlin.com/linux/latest/source/include/uapi/asm-generic/ioctl.h)
- [Rust for Linux](https://rust-for-linux.com/) — framework used by the driver
- [extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux) — to extract the kernel from bzImage
