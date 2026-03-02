# Inferno Sprint

**Category:** MISC
**Flag:** `EH4X{1nf3rn0_spr1n7_bl4z3_runn3r_m4573r}`

## Description

> The labyrinth burns. You have 90 seconds. Survive 5 rounds of increasingly brutal fire mazes. Dodge multi-speed fires, use portals, and escape to any edge — before the flames consume you.

## TL;DR

BFS pathfinding through fire mazes. Pre-compute fire arrival times via multi-source BFS (accounting for fire speed K = spreads every K turns), then BFS for the player to find shortest path to any edge cell that stays ahead of all fires. Portals handled as special "P" moves teleporting to the paired cell.

## Analysis

The server sends 5 rounds of hex-encoded grids with:
- `M` = player start, `.` = empty, `#` = wall
- `1/2/3` = fire sources with different speeds (speed K = spreads 1 cell every K turns)
- `a-e` = portal pairs (same letter = linked, `P` move teleports between them)

Goal: reach any edge cell before fire, within LIMIT moves, across 5 rounds in 90s total.

## Solution

1. **Decode** hex rows to ASCII grid
2. **Fire BFS**: multi-source BFS from all fire cells, propagating at rate K (next spread = current_time + speed). Compute `fire_time[r][c]` = when each cell catches fire
3. **Player BFS**: from start, expand WASD + portal moves. A move to `(r,c)` at turn `t+1` is valid if `fire_time[r][c] > t+1` (cell not yet burning)
4. First path reaching an edge cell wins

### Solve Script

See `solve.py`.

## Flag

```
EH4X{1nf3rn0_spr1n7_bl4z3_runn3r_m4573r}
```
