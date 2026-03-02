#!/usr/bin/env python3
"""solve.py — Andromeda Casino Cards solver
Accumulate player cards from 9 rounds (fold each), then play all 40 cards at once.
Player cards identified by Owner: "Account Address ( solver )".
"""
import socket, time, sys, re

HOST = sys.argv[1] if len(sys.argv) > 1 else '194.102.62.166'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 25595
MV_PATH = 'files/Andromeda_Casino-Cards/framework-solve/solve/build/solution/bytecode_modules/solution.mv'

def recv_until(s, marker, timeout=15):
    s.settimeout(timeout)
    data = b''
    start = time.time()
    while time.time() - start < timeout:
        try:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
            if marker.encode() in data: break
        except socket.timeout: break
    return data.decode('utf-8', errors='replace')

def send(s, msg):
    s.sendall((msg + '\n').encode())
    time.sleep(0.2)

def upload_module(s, name, mv_path):
    send(s, '1')
    recv_until(s, 'named address')
    send(s, name)
    recv_until(s, 'bytecode')
    with open(mv_path, 'rb') as f:
        data = f.read()
    s.sendall(data)
    time.sleep(0.5)
    r = recv_until(s, 'Select option:')
    ok = 'SUCCESS' in r
    print(f"Upload: {'OK' if ok else 'FAIL'}")
    return ok

def view_object(s, n1, n2):
    send(s, '2')
    recv_until(s, 'first number')
    send(s, str(n1))
    recv_until(s, 'second number')
    send(s, str(n2))
    r = recv_until(s, '---END---', timeout=5)
    send(s, 'ack')
    recv_until(s, 'Select option:', timeout=5)
    return r

def call_fn(s, pkg, mod_name, func, params, quiet=False):
    send(s, '3')
    recv_until(s, 'package name')
    send(s, pkg)
    recv_until(s, 'module name')
    send(s, mod_name)
    recv_until(s, 'function name')
    send(s, func)
    recv_until(s, 'number of parameters')
    send(s, str(len(params)))
    for p in params:
        recv_until(s, 'Enter type')
        if p[0] == 'object':
            send(s, 'object')
            recv_until(s, 'first number')
            send(s, str(p[1]))
            recv_until(s, 'second number')
            send(s, str(p[2]))
        elif p[0] == 'number':
            send(s, 'number')
            recv_until(s, 'number type')
            send(s, p[1])
            recv_until(s, 'value')
            send(s, str(p[2]))
        elif p[0] == 'immshared':
            send(s, 'immshared')
            recv_until(s, 'address')
            send(s, p[1])
        elif p[0] == 'object_vector':
            send(s, 'object_vector')
            recv_until(s, 'number of objects')
            objs = p[1]
            send(s, str(len(objs)))
            for j, (n1, n2) in enumerate(objs):
                recv_until(s, 'first number')
                send(s, str(n1))
                recv_until(s, 'second number')
                send(s, str(n2))
    r = recv_until(s, 'Select option:', timeout=15)
    ok = 'SUCCESS' in r
    if not quiet:
        print(f"  {func} -> {'OK' if ok else 'FAIL'}")
        if not ok:
            for line in r.split('\n'):
                if 'ERROR' in line:
                    print(f"    {line.strip()[:200]}")
    return r, ok

def parse_created(r):
    m = re.search(r'created:\s*(.*?)(?:mutated:|deleted:|unchanged|gas)', r, re.DOTALL)
    if m:
        return [(int(a), int(b)) for a, b in re.findall(r'object\((\d+),\s*(\d+)\)', m.group(1))]
    return []

def get_player_cards(s, created_objs):
    """Identify player cards: owned by solver account, not by an object."""
    player_cards = []
    for obj in created_objs:
        r = view_object(s, *obj)
        if 'Account Address' in r and 'solver' in r:
            player_cards.append(obj)
    return player_cards

def get_flag(s):
    send(s, '4')
    return recv_until(s, 'Select option:', timeout=10)

# Connect
s = socket.socket()
s.connect((HOST, PORT))
print(f"Connected to {HOST}:{PORT}")
recv_until(s, 'Select option:')
print("Ready")

# Find exchange and house
print("\n=== Find objects ===")
exchange_id = house_id = None
for i in range(12):
    r = view_object(s, 2, i)
    if 'ERROR' in r: break
    if 'claim_balance' in r:
        exchange_id = (2, i)
        print(f"  Exchange: (2,{i})")
    if 'is_round' in r and 'claim_balance' not in r:
        house_id = (2, i)
        print(f"  House: (2,{i})")

# Upload module
print("\n=== Upload ===")
assert upload_module(s, 'solution', MV_PATH)

# Claim coins
print("\n=== Claim 100 coins ===")
r, _ = call_fn(s, 'challenge', 'exchange', 'claim_coin', [('object', *exchange_id)])
coin_objs = parse_created(r)
main_coin = coin_objs[0]
print(f"  Coin: {main_coin}")

# Split into 10-coin portions
print("\n=== Split coins ===")
fee_coins = []
for i in range(9):
    r, ok = call_fn(s, 'solution', 'solution', 'split_coin', [
        ('object', *main_coin), ('number', 'u64', 10),
    ], quiet=True)
    if ok:
        new = parse_created(r)
        if new:
            fee_coins.append(new[0])
            print(f"  Split {i+1}: {new[0]}")

# Do 9 rounds: start, fold, collect player cards
print("\n=== Play 9 rounds ===")
all_cards = []
for rnd in range(9):
    fee = fee_coins[rnd]
    r, ok = call_fn(s, 'challenge', 'house', 'start_round', [
        ('object', *house_id), ('object', *fee), ('immshared', '0x8'),
    ], quiet=True)
    if not ok:
        print(f"  Round {rnd+1}: start FAILED")
        for line in r.split('\n'):
            if 'ERROR' in line: print(f"    {line.strip()[:200]}")
        continue

    created = parse_created(r)
    # Identify player cards (owned by solver account)
    player_cards = get_player_cards(s, created)
    all_cards.extend(player_cards)
    print(f"  Round {rnd+1}: got {len(player_cards)} player cards (total: {len(all_cards)})")

    # Fold using our Move module
    r, ok = call_fn(s, 'solution', 'solution', 'fold', [('object', *house_id)], quiet=True)
    if not ok:
        print(f"  Round {rnd+1}: fold FAILED")
        for line in r.split('\n'):
            if 'ERROR' in line: print(f"    {line.strip()[:200]}")

# Final round
print(f"\n=== Final round (total cards: {len(all_cards)}) ===")
r, ok = call_fn(s, 'challenge', 'house', 'start_round', [
    ('object', *house_id), ('object', *main_coin), ('immshared', '0x8'),
])
if ok:
    created = parse_created(r)
    final_player_cards = get_player_cards(s, created)
    all_cards.extend(final_player_cards)
    print(f"  Got {len(final_player_cards)} more cards (total: {len(all_cards)})")

    # Play all cards!
    print(f"\n=== PLAY {len(all_cards)} CARDS ===")
    r, ok = call_fn(s, 'challenge', 'house', 'play_hand', [
        ('object', *house_id),
        ('object_vector', all_cards),
    ])

    if ok:
        print("\n=== Claim rewards ===")
        r, ok = call_fn(s, 'challenge', 'house', 'claim_rewards', [('object', *house_id)])
        rewards = parse_created(r)
        print(f"  Reward coins: {rewards}")

        if rewards:
            print("\n=== SOLVE ===")
            call_fn(s, 'challenge', 'exchange', 'solve', [
                ('object', *exchange_id), ('object', *rewards[0]),
            ])

            print("\n=== FLAG ===")
            r = get_flag(s)
            print(r)

            m = re.search(r'UVT\{[^}]+\}', r)
            if m:
                flag = m.group()
                print(f"\nFLAG: {flag}")
                with open("flag.txt", "w") as f:
                    f.write(flag)

s.close()
