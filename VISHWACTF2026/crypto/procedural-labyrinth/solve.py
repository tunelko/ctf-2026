#!/usr/bin/env python3
from collections import deque, Counter

with open("index.html") as f:
    lines = [l.rstrip('\n') for l in f]

# Only maze lines: exactly 51 chars, only #.><
maze = [l for l in lines if len(l) == 51 and all(c in '#.><' for c in l)]
rows, cols = len(maze), 51
print(f"Maze: {rows}x{cols}")

start = end = None
for r, row in enumerate(maze):
    for c, ch in enumerate(row):
        if ch == '>': start = (r, c)
        if ch == '<': end = (r, c)
print(f"Start: {start}, End: {end}")

# BFS - memory efficient (store parent instead of full path)
parent = {start: None}
queue = deque([start])

while queue:
    r, c = queue.popleft()
    if (r, c) == end:
        break
    for dr, dc in [(0,1),(1,0),(0,-1),(-1,0)]:
        nr, nc = r+dr, c+dc
        if 0 <= nr < rows and 0 <= nc < cols and maze[nr][nc] != '#' and (nr, nc) not in parent:
            parent[(nr, nc)] = (r, c)
            queue.append((nr, nc))

# Reconstruct path
path = []
node = end
while node:
    path.append(node)
    node = parent.get(node)
path.reverse()
print(f"Path length: {len(path)}")

# Direction sequence
dir_map = {(0,1): 'R', (1,0): 'D', (0,-1): 'L', (-1,0): 'U'}
dirs = []
for i in range(1, len(path)):
    dr = path[i][0] - path[i-1][0]
    dc = path[i][1] - path[i-1][1]
    dirs.append(dir_map[(dr, dc)])

dir_str = ''.join(dirs)
print(f"Directions: {len(dirs)}")
print(f"Counts: {Counter(dirs)}")
print(f"First 300: {dir_str[:300]}")

# Try many encodings
print("\n=== ENCODING ATTEMPTS ===")

def bits_to_text(bits):
    out = ''
    for i in range(0, len(bits) - 7, 8):
        byte = int(bits[i:i+8], 2)
        out += chr(byte) if 32 <= byte <= 126 else '?'
    return out

# 1-bit: only horizontal
horiz = [d for d in dirs if d in ('R', 'L')]
print(f"\nHorizontal moves: {len(horiz)}")
print(f"  R=1,L=0: {bits_to_text(''.join('1' if d=='R' else '0' for d in horiz))[:120]}")
print(f"  R=0,L=1: {bits_to_text(''.join('0' if d=='R' else '1' for d in horiz))[:120]}")

# 1-bit: only vertical
vert = [d for d in dirs if d in ('D', 'U')]
print(f"\nVertical moves: {len(vert)}")
print(f"  D=1,U=0: {bits_to_text(''.join('1' if d=='D' else '0' for d in vert))[:120]}")
print(f"  D=0,U=1: {bits_to_text(''.join('0' if d=='D' else '1' for d in vert))[:120]}")

# 1-bit: all directions
for name, one, zero in [
    ("R/D=1,L/U=0", 'RD', 'LU'),
    ("R/U=1,L/D=0", 'RU', 'LD'),
]:
    bits = ''.join('1' if d in one else '0' for d in dirs)
    print(f"\n{name}: {bits_to_text(bits)[:120]}")

# 2-bit encodings
for name, m in [
    ("U=00,R=01,D=10,L=11", {'U':'00','R':'01','D':'10','L':'11'}),
    ("R=00,D=01,L=10,U=11", {'R':'00','D':'01','L':'10','U':'11'}),
    ("U=00,D=01,L=10,R=11", {'U':'00','D':'01','L':'10','R':'11'}),
    ("D=00,R=01,U=10,L=11", {'D':'00','R':'01','U':'10','L':'11'}),
    ("L=00,D=01,R=10,U=11", {'L':'00','D':'01','R':'10','U':'11'}),
    ("R=00,L=01,D=10,U=11", {'R':'00','L':'01','D':'10','U':'11'}),
]:
    bits = ''.join(m[d] for d in dirs)
    txt = bits_to_text(bits)
    if 'Vishwa' in txt or 'flag' in txt or 'CTF' in txt:
        print(f"\n*** FOUND: 2-bit {name}: {txt}")
    # Check for printable ratio
    printable = sum(1 for c in txt if c.isalnum())
    if printable > len(txt) * 0.5:
        print(f"\n2-bit {name} ({printable}/{len(txt)} alnum): {txt[:120]}")

# Maybe the path encodes turns? L-turn=0, R-turn=1
turns = []
for i in range(1, len(dirs)):
    if dirs[i] != dirs[i-1]:
        # Determine turn direction
        turn_map = {
            ('R','D'): 'R', ('D','L'): 'R', ('L','U'): 'R', ('U','R'): 'R',
            ('R','U'): 'L', ('U','L'): 'L', ('L','D'): 'L', ('D','R'): 'L',
        }
        t = turn_map.get((dirs[i-1], dirs[i]), '?')
        turns.append(t)
print(f"\nTurns: {len(turns)}, counts: {Counter(turns)}")
turn_bits = ''.join('1' if t == 'R' else '0' for t in turns if t in ('R', 'L'))
print(f"Turns R=1,L=0: {bits_to_text(turn_bits)[:120]}")
turn_bits2 = ''.join('0' if t == 'R' else '1' for t in turns if t in ('R', 'L'))
print(f"Turns R=0,L=1: {bits_to_text(turn_bits2)[:120]}")

# Run lengths per row
print("\n=== Run-length per row ===")
row_segs = {}
for r, c in path:
    row_segs.setdefault(r, []).append(c)
# For each row, count horizontal extent
extents = []
for r in sorted(row_segs.keys()):
    cols_in_row = row_segs[r]
    extent = max(cols_in_row) - min(cols_in_row)
    extents.append(extent)
print(f"Row extents (first 50): {extents[:50]}")

# Maybe the message is in run lengths of straight segments
seg_lens = []
cur = 1
for i in range(1, len(dirs)):
    if dirs[i] == dirs[i-1]:
        cur += 1
    else:
        seg_lens.append(cur)
        cur = 1
seg_lens.append(cur)
print(f"\nSegment lengths (first 80): {seg_lens[:80]}")
print(f"Total segments: {len(seg_lens)}")

# Maybe segment lengths map to ASCII?
ascii_segs = ''.join(chr(s) if 32 <= s <= 126 else '?' for s in seg_lens)
print(f"Segments as ASCII: {ascii_segs[:120]}")
