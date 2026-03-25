# ReadWriteMe - BSidesSF 2026 CTF

## Challenge Info
- **Category**: PWN
- **Author**: ron
- **Flag**: `CTF{no-more-secret-functions-alloweed}`

## TL;DR
Same arbitrary read/write as readwritecallme, but no secret_function. Leak libc via GOT hexdump, overwrite `strtoll@GOT` with `system`, send shell command as "address" input.

## Description
> Uh oh! We removed the secret function! Can you read the flag anyways?

## Analysis
Same binary structure as readwritecallme:
- `r` = arbitrary read (write memory to stdout)
- `h` = hexdump (print memory as hex)
- `w` = arbitrary write (fread from stdin to address)
- Partial RELRO (writable GOT)
- No secret_function this time — need to call into libc

## Exploit

### Step 1: Leak libc via GOT
Use `h` (hexdump) command to read `puts@GOT` (0x404008), 8 bytes → leaked puts libc address.

### Step 2: Calculate system address
```
libc base = puts_leaked - 0x77980  (puts offset in libc 2.36)
system    = libc_base   + 0x4c490  (system offset in libc 2.36)
```

### Step 3: Overwrite strtoll@GOT with system
Use `w` command to write system's address to `strtoll@GOT` (0x404028).

### Step 4: Trigger system with shell command
Send `r` command, then `cat /home/ctf/flag.txt` as the "address" string. When the program calls `strtoll(address_string, NULL, 16)` to parse the hex address, it actually calls `system("cat /home/ctf/flag.txt\n")` → flag printed!

### Why strtoll?
- `strtoll` is called with the user-provided address string as first argument (rdi)
- `system()` also takes a string as first argument
- Perfect argument reuse — no need for ROP or gadgets

## Flag
```
CTF{no-more-secret-functions-alloweed}
```

## Key Lessons
- With arbitrary read/write: leak libc from GOT → compute any libc function address
- Overwrite a GOT entry whose first argument you control with `system`
- `strtoll` is ideal: user provides the string, which becomes system's command argument
- No ROP needed — single GOT overwrite with controlled argument
