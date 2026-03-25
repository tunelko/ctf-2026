# hexhaustion — BSidesSF 2026 (Misc, 1000pts)

## TL;DR

Four QR codes encode quadrants of a 16x16 hex sudoku. Cells marked `?` along the main diagonal contain flag nibbles. Solve the sudoku, read the diagonal, convert hex to ASCII.

## Flag

```
CTF{HYPOAXIS}
```

## Description

Given 4 PNG images, each containing a QR code labeled "HEXHAUSTION 1-4". Each QR encodes one quadrant (8x8) of a 16x16 hex sudoku using values 0-F. Cells marked `?` are the flag nibbles.

## Steps

1. **Decode QR codes** — each contains an ASCII art grid representing one quadrant (Top Left, Top Right, Bottom Left, Bottom Right)
2. **Assemble the 16x16 grid** — combine the four 8x8 quadrants
3. **Identify flag cells** — `?` cells sit on the main diagonal: (0,0), (1,1), ..., (15,15) — 16 nibbles = 8 ASCII bytes
4. **Solve the 16x16 hex sudoku** — standard rules, 4x4 boxes, values 0-F
5. **Extract flag** — diagonal values `4859504F41584953` → ASCII `HYPOAXIS`

## Solve Script

```python
from PIL import Image
from pyzbar.pyzbar import decode
import re, copy

# --- Step 1: Decode QR codes ---
def parse_quadrant(text):
    """Parse ASCII art grid from QR data into 8x8 array"""
    rows = []
    for line in text.split('\n'):
        if '|' not in line or '=' in line or '-' in line:
            continue
        cells = []
        # Split by # (box border) and | (cell border)
        parts = re.split(r'[#|]', line)
        for p in parts:
            p = p.strip()
            if p == '':
                continue
            cells.append(p if p else '.')
        if len(cells) >= 1:
            rows.append(cells)
    return rows

quadrants = {}
labels = {1: 'TL', 2: 'TR', 3: 'BL', 4: 'BR'}

for i in range(1, 5):
    img = Image.open(f'release_qr_{i}.png')
    data = decode(img)[0].data.decode('utf-8')
    quadrants[i] = parse_quadrant(data)

# --- Step 2: Assemble 16x16 grid ---
# Manual parsing from QR data (verified against decoded text)
TL = [
    ['?','.','.','.','.','.','.','.'],['.','?','.','.','.','.','.','.'],['.','.',  '?','.','.','.','.','.'],['.','.','.','?','6','.','C','5'],
    ['.','.','.',  '4','?','.','D','7'],['.','.','.','.', '.','?','.','9'],
    ['.','.','.',  '6','E','.','?','.'],['.','.','.','D','3','2','.','?'],
]
TR = [
    ['.','.','.','.','.','.','.','.'],['.','.','.','.','.',  'B','1','C'],
    ['F','.','.','B','D','E','6','A'],['A','E','8','.','2','.','0','4'],
    ['.','.','.','.','.','.','.','.'],['C','.','.','F','6','4','.','.'],
    ['D','.','.','.',  'F','8','.','7'],['8','4','.','A','E','.','9','B'],
]
BL = [
    ['.','.','3','8','.','B','1','E'],['.','.','.',  '2','.','.','.',  'A'],
    ['.','.','.',  'A','.','.','.',  '.'],['.','.','F','.','.','9','.','4'],
    ['.','.','7','E','.','1','F','0'],['.','1','8','.','.','A','5','.'],
    ['.','2','4','C','.','.','.',  'B'],['.','5','D','0','.','.','9','C'],
]
BR = [
    ['?','.','A','.','.','.','.',  '.'],  ['.','?','F','6','7','.','.','.'  ],
    ['7','D','?','0','B','1','.',  'F'],  ['.','2','B','?','.','0','C','.'],
    ['.','C','6','.','?','D','.','2'],  ['.','.','0','E','C','?','7','6'],
    ['.','.','.',  'D','.','F','?','0'],  ['.','.','7','.','1','A','E','?'],
]

grid = []
for r in range(8):
    grid.append(TL[r] + TR[r])
for r in range(8):
    grid.append(BL[r] + BR[r])

# Track flag positions (main diagonal)
flag_positions = [(r, c) for r in range(16) for c in range(16) if grid[r][c] == '?']
print(f"Flag cells: {len(flag_positions)} on diagonal")

# --- Step 3: Convert to numeric ---
numeric = []
for r in range(16):
    row = []
    for c in range(16):
        v = grid[r][c]
        if v in ('.', '?'):
            row.append(-1)
        else:
            row.append(int(v, 16))
    numeric.append(row)

# --- Step 4: Solve 16x16 hex sudoku ---
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
                    # Eliminate from row, col, box
                    for c2 in range(N):
                        if c2 != c and val in poss[r][c2]:
                            poss[r][c2].discard(val); changed = True
                    for r2 in range(N):
                        if r2 != r and val in poss[r2][c]:
                            poss[r2][c].discard(val); changed = True
                    br, bc = (r//BOX)*BOX, (c//BOX)*BOX
                    for r2 in range(br, br+BOX):
                        for c2 in range(bc, bc+BOX):
                            if (r2,c2) != (r,c) and val in poss[r2][c2]:
                                poss[r2][c2].discard(val); changed = True
            # Hidden singles in rows, cols, boxes
            for unit in (
                [[(r,c) for c in range(N)] for r in range(N)] +
                [[(r,c) for r in range(N)] for c in range(N)] +
                [[(r,c) for r in range(br,br+BOX) for c in range(bc,bc+BOX)]
                 for br in range(0,N,BOX) for bc in range(0,N,BOX)]
            ):
                for val in range(N):
                    cells = [(r,c) for r,c in unit if val in poss[r][c]]
                    if len(cells) == 0: return False
                    if len(cells) == 1 and len(poss[cells[0][0]][cells[0][1]]) > 1:
                        poss[cells[0][0]][cells[0][1]] = {val}; changed = True
        return all(len(poss[r][c]) > 0 for r in range(N) for c in range(N))

    if not propagate():
        return None
    if all(len(poss[r][c]) == 1 for r in range(N) for c in range(N)):
        return [[next(iter(poss[r][c])) for c in range(N)] for r in range(N)]

    # Backtrack on cell with fewest candidates
    r, c = min(((r,c) for r in range(N) for c in range(N) if len(poss[r][c])>1),
               key=lambda rc: len(poss[rc[0]][rc[1]]))
    for val in list(poss[r][c]):
        new_grid = [row[:] for row in grid]
        new_grid[r][c] = val
        result = solve(new_grid)
        if result:
            return result
    return None

solution = solve(numeric)

# --- Step 5: Extract flag ---
flag_hex = ''.join(f'{solution[r][c]:X}' for r, c in flag_positions)
flag_ascii = bytes.fromhex(flag_hex).decode()

print(f"\nSolved grid:")
for r in range(16):
    print(' '.join(f'{v:X}' for v in solution[r]))

print(f"\nDiagonal nibbles: {flag_hex}")
print(f"Flag: CTF{{{flag_ascii}}}")
# CTF{HYPOAXIS}
```

## Output

```
Diagonal nibbles: 4859504F41584953
Flag: CTF{HYPOAXIS}
```

## Key Insight

- "hexhaustion" = hex + exhaustion
- 16x16 sudoku with hex digits (0-F), 4x4 boxes
- Flag nibbles placed on the main diagonal — 16 nibbles = 8 bytes of ASCII
- The hint "4 nibbles" in the description = 4 QR images, each a quadrant
