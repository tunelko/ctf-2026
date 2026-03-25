# wromwarp — BSidesSF 2026 (Pwn RE, 289pts)

## TL;DR

Custom 8-bit emulator ("LES") with a debugger. Flag is at WRAM address 0xF0 but `printflag.les` ROM isn't on the server. Exploit the fact that `/load` changes the ROM without resetting CPU state — switch between ROMs mid-execution to construct `mR=0xF0` using instructions from different games, then trigger `PRINT` to display the flag.

## Flag

```
CTF{new_tas_wr}
```

## Description

We're given source code and binary for "wromwarp", an ncurses-based emulator/debugger for the fictional "Lonely Entertainment System" (LES). The LES has:
- 8-bit registers (gA-gD, mR, mW, pA, pB, cursor/input regs)
- 256 bytes WRAM (loaded from `WRAM.bin` on startup/INIT)
- 4096-word ROM
- 32x32 pixel display + 32-char text display
- Debugger REPL: `/load`, `/step`, `/run`, `/break`, `/reset`, etc.

The flag is stored at WRAM offset 0xF0 (loaded from `WRAM.bin`). A `printflag.les` ROM is provided locally but **not on the server**. Available server ROMs: snake, pong, flappy, lunar, life, minesweeper, pixtest.

## Vulnerability: ROM Switching Preserves CPU State

The `/load` command replaces the ROM program but **does NOT reset the CPU**:

```c
// process_command → /load handler
emu->program = p;      // replaces ROM
emu->loaded = true;    // that's it — no cpu_reset()!
```

This means registers (including `mR`, call stack `spc[]`) survive across ROM loads. By loading different ROMs at strategic moments and `/step`-ping, we can execute instructions from different games in sequence — a **TAS (Tool-Assisted Speedrun)** across ROMs.

## Exploit Strategy

**Goal**: Set `mR = 0xF0 (240)` and execute `PRINT` (which displays WRAM starting at `mR`).

**Key instructions across ROMs at specific PCs**:

| PC | ROM | Instruction | Effect |
|----|-----|-------------|--------|
| 0 | any | `INIT` | Reset CPU, load WRAM (flag at 0xF0) |
| 11 | pong | `CALL <UPDATE_PUCK_SUBPIXEL>` | Saves return address **12** to call stack, jumps to PC 48 |
| 103 | life | `SET 48, gA` | gA = 48 |
| 147 | lunar | `CALL <CLAMP_GA_11>` | Saves return address 148, **skips PC 152** (which clobbers gA in ALL ROMs), jumps to PC 173 |
| 186 | lunar | `SUB 0, gA, gA` | gA = 0 - 48 = **208** (uint8 wrapping) |
| 234 | pong | `SETP 1, pA` | Neutral — skips lunar's `AND gA, 31, gA` which would mask gA |
| 235 | lunar | `ADD gA, 32, mR` | mR = 208 + 32 = **240 = 0xF0** |
| 240 | lunar | `RET` | Returns to PC 148 (second call's return address) |
| 151 | flappy | `RET` | Returns to PC **12** (first call's return address) |
| 12 | pixtest | `PRINT` | Displays WRAM[240..] = **FLAG** |

**Critical insight**: Nested `CALL`/`RET` creates a return chain: PC 12 is where both pixtest and flappy have `PRINT`. The first CALL at PC 11 saves return address 12. After all manipulations, two RETs unwind back to PC 12.

**PC 152 problem**: At PC 152, ALL available ROMs modify `gA` (RND, LOAD, DUPE, or control flow). The second CALL at PC 147 jumps to PC 173, **skipping PC 152 entirely** while preserving gA=48.

## Exploit

Between the key instructions, ~180 intermediate PCs need "neutral" ROMs (instructions that don't modify critical registers or change control flow). A script computes the optimal ROM for each PC and generates 264 commands (79 `/load` + 185 `/step`).

```python
# Automated solver (connects to port 6502, sends commands)
import socket, time

commands = open('/tmp/wromwarp_cmds.txt').readlines()  # pre-computed

sock = socket.socket()
sock.connect(("wromwarp-....challenges.bsidessf.net", 6502))
time.sleep(4)  # wait for startup
sock.recv(8192)

for cmd in commands:
    cmd = cmd.strip()
    for ch in cmd:
        sock.sendall(ch.encode())
        time.sleep(0.01)
    sock.sendall(b'\r')
    time.sleep(0.2)
    sock.recv(8192)

# TEXT pane now shows: CTF{new_tas_wr}
```

## Key Lessons

- `/load` not resetting CPU state is a classic emulator bug — state persistence across ROM loads enables cross-ROM instruction chaining
- Challenge name "wromwarp" = WRAM + warp (warping WRAM access via register manipulation)
- The flag text "new_tas_wr" references TAS (Tool-Assisted Speedrun) — the technique of frame-perfect input manipulation, here applied to ROM switching
- Nested CALL/RET provides both skip-over capability (bypassing problematic PCs) and return-to-target (reaching PRINT at PC 12)
- The 5×5 Polybius grid of available instructions across ROMs × PCs is the actual puzzle space
