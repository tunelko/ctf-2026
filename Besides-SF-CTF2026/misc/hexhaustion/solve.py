#!/usr/bin/env python3
"""hexhaustion solver — BSidesSF 2026"""

from PIL import Image
from pyzbar.pyzbar import decode

# --- Step 1: Decode QR codes and manually parse grids ---
# (QR data is ASCII art; hardcoded after verification)

TL = [  # Top Left (rows 0-7, cols 0-7)
    ['?','.','.','.','.','.','.','.'],['.','?','.','.','.','.','.','.'],
    ['.','.',  '?','.','.','.','.','.'],['.','.','.','?','6','.','C','5'],
    ['.','.','.',  '4','?','.','D','7'],['.','.','.','.', '.','?','.','9'],
    ['.','.','.',  '6','E','.','?','.'],['.','.','.','D','3','2','.','?'],
]
TR = [  # Top Right (rows 0-7, cols 8-15)
    ['.','.','.','.','.','.','.','.'],['.','.','.','.','.',  'B','1','C'],
    ['F','.','.','B','D','E','6','A'],['A','E','8','.','2','.','0','4'],
    ['.','.','.','.','.','.','.','.'],['C','.','.','F','6','4','.','.'],
    ['D','.','.','.',  'F','8','.','7'],['8','4','.','A','E','.','9','B'],
]
BL = [  # Bottom Left (rows 8-15, cols 0-7)
    ['.','.','3','8','.','B','1','E'],['.','.','.',  '2','.','.','.',  'A'],
    ['.','.','.',  'A','.','.','.',  '.'],['.','.','F','.','.','9','.','4'],
    ['.','.','7','E','.','1','F','0'],['.','1','8','.','.','A','5','.'],
    ['.','2','4','C','.','.','.',  'B'],['.','5','D','0','.','.','9','C'],
]
BR = [  # Bottom Right (rows 8-15, cols 8-15)
    ['?','.','A','.','.','.','.','.'],['.','?','F','6','7','.','.','.'],
    ['7','D','?','0','B','1','.','F'],['.','2','B','?','.','0','C','.'],
    ['.','C','6','.','?','D','.','2'],['.','.','0','E','C','?','7','6'],
    ['.','.','.',  'D','.','F','?','0'],['.','.','7','.','1','A','E','?'],
]

# Assemble 16x16
grid = [TL[r] + TR[r] for r in range(8)] + [BL[r] + BR[r] for r in range(8)]
flag_pos = [(i, i) for i in range(16)]  # main diagonal

# Convert to numeric (-1 = unknown)
numeric = []
for r in range(16):
    numeric.append([int(v, 16) if v not in ('.', '?') else -1 for v in grid[r]])

# --- Solve 16x16 hex sudoku ---
def solve(grid):
    N, BOX = 16, 4
    poss = [[set(range(N)) for _ in range(N)] for _ in range(N)]
    for r in range(N):
        for c in range(N):
            if grid[r][c] >= 0:
                poss[r][c] = {grid[r][c]}

    def propagate():
        changed = True
        while changed:
            changed = False
            for r in range(N):
                for c in range(N):
                    if len(poss[r][c]) != 1:
                        continue
                    val = next(iter(poss[r][c]))
                    for c2 in range(N):
                        if c2 != c and val in poss[r][c2]:
                            poss[r][c2].discard(val); changed = True
                    for r2 in range(N):
                        if r2 != r and val in poss[r2][c]:
                            poss[r2][c].discard(val); changed = True
                    br, bc = (r // BOX) * BOX, (c // BOX) * BOX
                    for r2 in range(br, br + BOX):
                        for c2 in range(bc, bc + BOX):
                            if (r2, c2) != (r, c) and val in poss[r2][c2]:
                                poss[r2][c2].discard(val); changed = True
            for unit in (
                [[(r, c) for c in range(N)] for r in range(N)] +
                [[(r, c) for r in range(N)] for c in range(N)] +
                [[(r, c) for r in range(br, br + BOX) for c in range(bc, bc + BOX)]
                 for br in range(0, N, BOX) for bc in range(0, N, BOX)]
            ):
                for val in range(N):
                    cells = [(r, c) for r, c in unit if val in poss[r][c]]
                    if len(cells) == 0:
                        return False
                    if len(cells) == 1 and len(poss[cells[0][0]][cells[0][1]]) > 1:
                        poss[cells[0][0]][cells[0][1]] = {val}; changed = True
        return all(len(poss[r][c]) > 0 for r in range(N) for c in range(N))

    if not propagate():
        return None
    if all(len(poss[r][c]) == 1 for r in range(N) for c in range(N)):
        return [[next(iter(poss[r][c])) for c in range(N)] for r in range(N)]

    r, c = min(((r, c) for r in range(N) for c in range(N) if len(poss[r][c]) > 1),
               key=lambda rc: len(poss[rc[0]][rc[1]]))
    for val in list(poss[r][c]):
        new_grid = [row[:] for row in grid]
        new_grid[r][c] = val
        result = solve(new_grid)
        if result:
            return result
    return None

solution = solve(numeric)

# Extract flag
flag_hex = ''.join(f'{solution[r][c]:X}' for r, c in flag_pos)
flag = bytes.fromhex(flag_hex).decode()
print(f"Diagonal: {flag_hex}")
print(f"Flag: CTF{{{flag}}}")
# CTF{HYPOAXIS}
