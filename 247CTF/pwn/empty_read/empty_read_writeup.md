# empty_read - 247CTF Challenge Analysis

## Challenge Info
- **URL**: `tcp://c737f3fcdedba906.247ctf.com:50304`
- **Description**: "We are working on a simple service to store email addresses. Currently you can only store 10 addresses, but that should be enough for now. One of our beta testers complained about a few bugs, but we think they were just reading too much into it."
- **Hint**: "reading too much into it" suggests vulnerability relates to read operations

## Binary Analysis

### Basic Info
- 32-bit PIE executable, dynamically linked, stripped
- libc 2.27 (Ubuntu GLIBC 2.27-3ubuntu1)
- Functions: setbuf, read, printf, free, fgets, malloc, puts, fopen, memset, atoi, strncmp

### Commands
- `debug` - prints libc version
- `print` - prints all user emails
- `add` - add a new user (index 0-9)
- `edit` - edit a user's email
- `delete` - delete a user
- `exit` - exit program

### Data Structure
```c
struct user {
    int size;       // offset 0 - email buffer size
    char *email;    // offset 4 - pointer to email buffer
};
// Array of 10 user pointers stored in .bss
```

### Function Analysis

#### add (fcn.000008ab)
1. Reads user index (0-9)
2. Validates index and checks slot is empty
3. Allocates struct: `malloc(8)`
4. Reads email length
5. **Size clamping**: if `length <= 0` OR `length > 0x200`, clamps to `0x200`
6. Stores clamped length in `user->size`
7. Allocates email buffer: `malloc(user->size)`
8. Reads email: `read(0, user->email, user->size)`
9. **Null termination**:
   - If read > 0: `email[bytes_read] = 0`
   - If read <= 0: `email[0] = 0`

#### edit (fcn.00000ac0)
1. Reads user index
2. Validates index 0-9 and user exists
3. Reads email: `read(0, user->email, user->size)` using **stored size**
4. Same null termination logic as add

#### delete (fcn.00000be4)
1. Reads user index
2. Validates index 0-9 and user exists
3. If `user->email != NULL`: `free(user->email)`, `user->email = 0`
4. `memset(user, 0, 8)` - **zeros the struct**
5. `free(user)`
6. `users[idx] = NULL`

#### print (fcn.00000839)
- Iterates through users 0-9
- For each non-NULL user: `printf("User %d email: %s", idx, user->email)`

## Potential Vulnerabilities Investigated

### 1. Off-by-one NULL byte
- When read returns exactly `size` bytes, `email[size] = 0` writes one byte past buffer
- This writes to `next_chunk[0]` (prev_size field), not directly exploitable for tcache poisoning

### 2. Heap Layout with tcache
- struct (8 bytes) and small emails share same tcache bin (0x10)
- Memory reuse follows LIFO pattern
- Delete properly clears struct (memset) before free

### 3. Leak via tcache pointers
- Freed chunks contain next pointers at offset 0
- Attempted to preserve partial pointer with size=1 write
- Printf %s stops at null bytes, making leak difficult

### 4. Failed email allocation
- If email malloc fails, struct remains allocated with email=NULL
- Edit on such user would crash (read to NULL address)

## Exploit Development Status

### Working primitives
- Basic heap manipulation with tcache
- Memory reuse confirmed (same-size chunks reused)

### Next steps to investigate
1. **Off-by-one heap corruption**: Need to find exact chunk layout to corrupt something useful
2. **Tcache key bypass**: glibc 2.27 has no tcache key, simpler poisoning possible
3. **Heap leak technique**: Find way to leak heap address despite printf %s limitation
4. **Consider format string**: Check if any printf call is vulnerable (didn't see obvious one)
5. **Size confusion**: What if we can make stored size larger than actual buffer?

## Test Scripts

### exploit_dev.py - Contains helper functions for interaction
```python
def send_num(r, n):
    r.send(str(n).encode().ljust(4, b'\n')[:4])

def add(r, idx, length, email):
    cmd(r, b'add')
    r.recvuntil(b'User index to add:')
    send_num(r, idx)
    r.recvuntil(b'User email length:')
    send_num(r, length)
    r.recvuntil(b'User email:')
    actual_len = length if 0 < length <= 0x200 else 0x200
    r.send(email.ljust(actual_len, b'\x00')[:actual_len])

def edit(r, idx, email, length):
    cmd(r, b'edit')
    r.recvuntil(b'User index to edit:')
    send_num(r, idx)
    r.recvuntil(b'User email:')
    r.send(email.ljust(length, b'\x00')[:length])

def delete(r, idx):
    cmd(r, b'delete')
    r.recvuntil(b'User index to delete:')
    send_num(r, idx)
```

## Key Observations
1. The challenge name "empty_read" and hint "reading too much into it" strongly suggest the bug is in read() behavior
2. Possible interpretations:
   - Reading from empty/uninitialized buffer
   - Reading more than buffer size (via corrupted stored size)
   - Reading from freed memory
3. libc 2.27 tcache is relatively easy to exploit once we have a write primitive
4. PIE means we need a leak before any meaningful exploitation
