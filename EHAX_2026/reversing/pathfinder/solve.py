#!/usr/bin/env python3
"""Pathfinder solver - EHAXctf reversing challenge"""
from collections import deque

# === GRID INITIALIZATION ===
# entry.init1: grid[i] = data_0x2020[i] ^ scramble(i)
def scramble(i):
    return ((i * 32 - i + 0x11) ^ (i * 8) ^ 0xffffffa5) & 0xFF

# Pre-computed grid (10x10)
GRID = [
     8, 10, 12,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  5,  0,  0,  8, 10, 10, 12,  0,
     0,  0,  3,  0,  0,  5,  0,  0,  5,  0,
     8, 10, 10, 10, 10,  1,  0,  0,  5,  0,
     5,  0,  0,  0,  0,  0,  8, 10,  1,  0,
     5,  0, 12, 10, 12,  0,  5,  0,  0,  0,
     5,  0,  5,  0,  5,  0,  5,  0,  0,  0,
     5,  0,  1,  0,  3, 10,  9,  0,  8, 12,
     5,  0,  0,  0,  0,  0,  0,  0,  5,  5,
     3, 10, 10, 10, 10, 10, 10, 10,  1,  3,
]

# === MOVEMENT TABLE ===
# entry.init2 initializes: char -> (d_row, d_col, f1, f2, enabled)
# Scramble per step: s1 = (ord(ch) * 0x6b) ^ f1 ^ 0x3c
#                    s2 = (ord(ch) * 0x6b) ^ f2 ^ 0x3c
MOVES = {
    'N': (-1,  0, 0xa2, 0xa7),  # UP
    'S': ( 1,  0, 0x8c, 0x89),  # DOWN
    'E': ( 0,  1, 0xe9, 0xe3),  # RIGHT
    'W': ( 0, -1, 0x69, 0x63),  # LEFT
}

# === HASH FUNCTION (fcn.0000126b) ===
def path_hash(s):
    h = 0xDEADBEEF
    for c in s:
        h ^= ord(c)
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 0x045d9f3b) & 0xFFFFFFFF
    h ^= (h >> 16)
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= (h >> 13)
    return h

# === VALIDATION LOGIC (fcn.00001444) ===
def validate_path(path):
    row, col = 0, 0
    for ch in path:
        if ch not in MOVES:
            return False
        dr, dc, f1, f2 = MOVES[ch]
        s1 = ((ord(ch) * 0x6b) ^ f1 ^ 0x3c) & 0xFF
        s2 = ((ord(ch) * 0x6b) ^ f2 ^ 0x3c) & 0xFF
        nr, nc = row + dr, col + dc
        if nr < 0 or nr > 9 or nc < 0 or nc > 9:
            return False
        cell1 = GRID[row * 10 + col]
        cell2 = GRID[nr * 10 + nc]
        if (cell1 & s1) | (cell2 & s2) == 0:
            return False
        row, col = nr, nc
    if row != 9 or col != 9:
        return False
    if path_hash(path) != 0x86ba520c:
        return False
    return True

# === FLAG CONSTRUCTION (fcn.00001602) ===
def build_flag(path):
    """RLE encode path and wrap in EHAX{...}"""
    result = "EHAX{"
    i = 0
    while i < len(path):
        ch = path[i]
        count = 1
        while i + count < len(path) and path[i + count] == ch:
            count += 1
        if count > 1:
            result += f"{count}{ch}"
        else:
            result += ch
        i += count
    result += "}"
    return result

# === BFS SOLVER ===
def solve():
    valid_dirs = []
    for ch, (dr, dc, f1, f2) in MOVES.items():
        s1 = ((ord(ch) * 0x6b) ^ f1 ^ 0x3c) & 0xFF
        s2 = ((ord(ch) * 0x6b) ^ f2 ^ 0x3c) & 0xFF
        valid_dirs.append((ch, dr, dc, s1, s2))

    queue = deque([(0, 0, "")])
    visited = {(0, 0)}

    while queue:
        row, col, path = queue.popleft()
        if row == 9 and col == 9:
            return path
        for ch, dr, dc, s1, s2 in valid_dirs:
            nr, nc = row + dr, col + dc
            if nr < 0 or nr > 9 or nc < 0 or nc > 9:
                continue
            if (nr, nc) in visited:
                continue
            cell1 = GRID[row * 10 + col]
            cell2 = GRID[nr * 10 + nc]
            if (cell1 & s1) | (cell2 & s2) == 0:
                continue
            visited.add((nr, nc))
            queue.append((nr, nc, path + ch))

    return None

if __name__ == "__main__":
    path = solve()
    if path:
        print(f"Path: {path}")
        print(f"Length: {len(path)}")
        print(f"Hash: {path_hash(path):#010x} (target: 0x86ba520c)")
        print(f"Valid: {validate_path(path)}")
        print(f"Flag: {build_flag(path)}")
    else:
        print("No path found!")
