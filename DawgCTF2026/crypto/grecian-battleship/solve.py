#!/usr/bin/env python3
"""
Grecian Battleship - DawgCTF 2026
Category: crypto

PyInstaller-packed tkinter Battleship game on a 5x5 grid (GRID_SIZE=5).
All 4 ships are size 2. AI uses a hardcoded move_script instead of random moves.

The 5x5 grid + "Can you beat the Ancient Greeks?" → Polybius square cipher.
The Polybius square was invented by the Greek historian Polybius (~200-118 BC).
Each cell (row, col) in the 5x5 grid maps to a letter of the alphabet.

Extract move_script from bytecode, decode via standard Polybius square.
"""

# AI's scripted attack moves (extracted from battleship.pyc __init__)
move_script = [(2,4),(2,3),(2,1),(0,0),(1,1),(3,1),(3,4),(2,2),(0,4),(3,3)]

# Standard Polybius square (I/J combined), 0-indexed
polybius = [
    ['A','B','C','D','E'],
    ['F','G','H','I','K'],
    ['L','M','N','O','P'],
    ['Q','R','S','T','U'],
    ['V','W','X','Y','Z']
]

flag_content = ''.join(polybius[r][c] for r, c in move_script)
print(f"[+] FLAG: DawgCTF{{{flag_content}}}")
