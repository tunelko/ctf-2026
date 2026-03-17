# Fluffy Game - Writeup

**CTF**: Midnight Flag 2026
**Category**: Reversing
**Author**: fun88337766
**Flag**: `MCTF{YOu_KnOw_hOw_To_Ch34T_3nGiNe_R1GhT}`

## TL;DR

PyInstaller-packed Flappy Bird clone with anti-cheat. Extract Python bytecode, reverse the proof-of-play hash chain, replay it against the server API to get the flag image.

## Analysis

`game.exe` is a PyInstaller PE32+ executable (Python 3.13). Extracted with `pyinstxtractor`, decompiled `game.pyc` with `pycdc` + `dis` module.

The game has two levels and communicates with `https://cheat-or-not-cheat-production.up.railway.app`. Many fake flags are scattered as honeypots (`MCTF{d43m0n_h00k_d3t3ct3d}`, `MCTF{f4k3_b34r3r_t0k3n_992}`, etc.).

## Server Protocol

1. `GET /init_session` → `{session_id, seed}`
2. Game plays Level 1 (score 6666) + Level 2 (score 25 in timer)
3. `POST /request_flag_link` with `{session_id, score, ticks, proof}` → `{one_time_token}`
4. `GET /get_flag_image?token=TOKEN` → flag PNG image

## Proof Computation

From bytecode disassembly of `lancer_niveau_2`:

```python
random.seed(GLOBAL_SEED)
final_proof = str(GLOBAL_SEED)

# Initial 4 pipe heights
for _ in range(4):
    h = random.randint(40, 320)  # MIN_H, MAX_H
    final_proof = hashlib.sha256(f"{final_proof}_{h}".encode()).hexdigest()

# Game tick loop - only hash every 88th tick
for t_tick in range(1, ticks + 1):
    if t_tick % 88 != 0:
        continue
    h = random.randint(40, 320)
    final_proof = hashlib.sha256(f"{final_proof}_{h}".encode()).hexdigest()
```

Key insight: the `t_tick % 88 == 0` check (bytecode `BINARY_OP 6` = modulo) means only every 88th tick contributes to the hash chain.

## Solve Script

```python
import requests, hashlib, random

SERVER = "https://cheat-or-not-cheat-production.up.railway.app"

r = requests.get(f"{SERVER}/init_session").json()
session_id, seed_val = r["session_id"], r["seed"]

random.seed(seed_val)
final_proof = str(seed_val)
for _ in range(4):
    h = random.randint(40, 320)
    final_proof = hashlib.sha256(f"{final_proof}_{h}".encode()).hexdigest()

ticks = 500
for t_tick in range(1, ticks + 1):
    if t_tick % 88 != 0:
        continue
    h = random.randint(40, 320)
    final_proof = hashlib.sha256(f"{final_proof}_{h}".encode()).hexdigest()

payload = {"session_id": session_id, "score": 25, "ticks": ticks, "proof": final_proof}
token = requests.post(f"{SERVER}/request_flag_link", json=payload).json()["one_time_token"]

r2 = requests.get(f"{SERVER}/get_flag_image", params={"token": token})
with open("flag.png", "wb") as f:
    f.write(r2.content)
```
