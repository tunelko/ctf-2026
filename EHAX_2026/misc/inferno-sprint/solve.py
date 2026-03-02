#!/usr/bin/env python3
# solve.py — Inferno Sprint maze solver
# BFS through fire mazes with multi-speed fires and portals

from pwn import *
from collections import deque
import sys

context.log_level = 'info'

HOST = 'chall.ehax.in'
PORT = 31337

def decode_grid(hex_rows, rows, cols):
    """Decode hex-encoded rows into a 2D character grid."""
    grid = []
    for hex_row in hex_rows:
        row = bytes.fromhex(hex_row).decode()
        grid.append(list(row))
    return grid

def precompute_fire(grid, rows, cols):
    """
    BFS from all fire sources simultaneously.
    Returns fire_time[r][c] = the turn at which cell (r,c) catches fire.
    Fire with speed K spreads 1 cell every K turns.
    """
    INF = float('inf')
    fire_time = [[INF] * cols for _ in range(rows)]

    # Queue: (turn_fire_arrives, r, c, speed)
    q = deque()

    for r in range(rows):
        for c in range(cols):
            ch = grid[r][c]
            if ch in '123':
                speed = int(ch)
                fire_time[r][c] = 0
                q.append((0, r, c, speed))

    while q:
        t, r, c, speed = q.popleft()
        next_t = t + speed  # fire spreads 1 cell every 'speed' turns
        for dr, dc in [(-1,0),(1,0),(0,-1),(0,1)]:
            nr, nc = r + dr, c + dc
            if 0 <= nr < rows and 0 <= nc < cols:
                if grid[nr][nc] != '#' and next_t < fire_time[nr][nc]:
                    fire_time[nr][nc] = next_t
                    q.append((next_t, nr, nc, speed))

    return fire_time

def solve_maze(grid, rows, cols, start_r, start_c, move_limit):
    """
    BFS to find shortest path from start to any edge cell,
    avoiding fire and walls. Returns move string or None.
    """
    fire_time = precompute_fire(grid, rows, cols)

    # Find portals
    portals = {}  # letter -> list of (r, c)
    for r in range(rows):
        for c in range(cols):
            ch = grid[r][c]
            if ch in 'abcde':
                portals.setdefault(ch, []).append((r, c))

    # Portal lookup: (r,c) -> (dest_r, dest_c)
    portal_dest = {}
    for letter, positions in portals.items():
        if len(positions) == 2:
            portal_dest[positions[0]] = positions[1]
            portal_dest[positions[1]] = positions[0]

    # BFS: state = (r, c), track turn number
    # visited[r][c] = earliest turn we reached it
    INF = float('inf')
    visited = [[INF] * cols for _ in range(rows)]

    # Check start is safe at turn 0
    if fire_time[start_r][start_c] <= 0:
        return None

    visited[start_r][start_c] = 0
    # Queue: (r, c, turn, path)
    q = deque()
    q.append((start_r, start_c, 0, ''))

    # Edge check
    def is_edge(r, c):
        return r == 0 or r == rows - 1 or c == 0 or c == cols - 1

    # If start is already on edge
    if is_edge(start_r, start_c):
        return ''

    moves = {'W': (-1, 0), 'S': (1, 0), 'A': (0, -1), 'D': (0, 1)}

    while q:
        r, c, turn, path = q.popleft()

        if turn >= move_limit:
            continue

        next_turn = turn + 1

        # Try WASD moves
        for move_char, (dr, dc) in moves.items():
            nr, nc = r + dr, c + dc
            if 0 <= nr < rows and 0 <= nc < cols:
                if grid[nr][nc] != '#':
                    # Cell must not be on fire at next_turn
                    if fire_time[nr][nc] > next_turn and next_turn < visited[nr][nc]:
                        visited[nr][nc] = next_turn
                        new_path = path + move_char
                        if is_edge(nr, nc):
                            return new_path
                        q.append((nr, nc, next_turn, new_path))

        # Try portal
        if (r, c) in portal_dest:
            dr, dc = portal_dest[(r, c)]
            if fire_time[dr][dc] > next_turn and next_turn < visited[dr][dc]:
                visited[dr][dc] = next_turn
                new_path = path + 'P'
                if is_edge(dr, dc):
                    return new_path
                q.append((dr, dc, next_turn, new_path))

    return None

def main():
    p = remote(HOST, PORT)

    # Read banner until BEGIN
    p.recvuntil(b'BEGIN\n')

    for round_num in range(1, 6):
        log.info(f'=== Round {round_num}/5 ===')

        # Parse round header
        # Read lines until we get SIZE, START, LIMIT
        while True:
            line = p.recvline().decode().strip()
            log.info(f'Header: {line}')
            if line.startswith('SIZE'):
                break
        parts = line.split()
        rows, cols = int(parts[1]), int(parts[2])
        log.info(f'Size: {rows}x{cols}')

        line = p.recvline().decode().strip()  # START r c
        parts = line.split()
        start_r, start_c = int(parts[1]), int(parts[2])
        log.info(f'Start: ({start_r}, {start_c})')

        line = p.recvline().decode().strip()  # LIMIT n
        move_limit = int(line.split()[1])
        log.info(f'Limit: {move_limit}')

        # Read hex rows
        hex_rows = []
        for i in range(rows):
            hex_row = p.recvline().decode().strip()
            hex_rows.append(hex_row)

        # Decode grid
        grid = decode_grid(hex_rows, rows, cols)

        # Debug: print grid
        for r in range(rows):
            log.debug(''.join(grid[r]))

        # Solve
        path = solve_maze(grid, rows, cols, start_r, start_c, move_limit)

        if path is None:
            log.error(f'No solution found for round {round_num}!')
            # Try just going to nearest edge
            path = 'W' * move_limit
            log.warning(f'Sending fallback: {path}')

        log.info(f'Path ({len(path)} moves): {path}')

        # Send path
        p.recvuntil(b'PATH> ')
        p.sendline(path.encode())

        # Read result
        result = p.recvline().decode().strip()
        log.info(f'Result: {result}')

        if 'FAIL' in result:
            log.error('Failed!')
            # Try to read more
            try:
                extra = p.recvall(timeout=3)
                print(extra.decode(errors='replace'))
            except:
                pass
            break

    # Read flag
    try:
        remaining = p.recvall(timeout=10)
        output = remaining.decode(errors='replace')
        print(output)
        for line in output.split('\n'):
            if '{' in line and '}' in line:
                flag = line.strip()
                print(f'\nFLAG: {flag}')
                with open('flag.txt', 'w') as f:
                    f.write(flag)
                break
    except:
        pass

    p.close()

if __name__ == '__main__':
    main()
