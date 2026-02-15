#!/usr/bin/env python3
"""
Chip8 Emulator - Solve
Creates a 4-instruction CHIP-8 ROM that triggers the hidden opcode FxFF
and runs the emulator to generate flag.txt with the decrypted flag.

Flag: 0xfunCTF2025{N0w_y0u_h4v3_clear_1dea_H0w_3mulators_WoRK}
"""
import struct
import subprocess
import os

# --- Step 1: Create ROM with the flaw opcode ---
# "quad cycles" = 4 instructions
# The opcode FxFF does not exist in standard CHIP-8 - it's the "flaw"
# The emulator intercepts it and executes superChipRendrer() which decrypts the flag
rom = b''
rom += struct.pack('>H', 0x6000)  # LD V0, 0x00
rom += struct.pack('>H', 0x6100)  # LD V1, 0x00
rom += struct.pack('>H', 0x6200)  # LD V2, 0x00
rom += struct.pack('>H', 0xF0FF)  # FxFF -> superChipRendrer() -> decrypts flag

rom_path = '/tmp/flaw.ch8'
with open(rom_path, 'wb') as f:
    f.write(rom)
print(f"[+] ROM created: {rom_path} ({len(rom)} bytes)")
print(f"[+] Opcodes: {rom.hex()}")

# --- Step 2: Run the emulator ---
emulator = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'the_Chip8_Emulator', 'chip8Emulator')
os.chmod(emulator, 0o755)

# Needs virtual display (xvfb) and dummy audio
cmd = ['xvfb-run', '-a', 'env', 'SDL_AUDIODRIVER=dummy',
       emulator, '-r', rom_path, '-l', '0']

print(f"[+] Running: {' '.join(cmd)}")
try:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                           cwd=os.path.dirname(emulator))
except subprocess.TimeoutExpired:
    pass

# --- Step 3: Read the flag ---
flag_path = os.path.join(os.path.dirname(emulator), 'flag.txt')
if os.path.exists(flag_path):
    with open(flag_path) as f:
        flag = f.read().strip()
    print(f"[+] Flag: {flag}")
else:
    print("[-] flag.txt not found")
