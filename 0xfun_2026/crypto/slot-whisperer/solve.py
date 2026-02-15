#!/usr/bin/env python3
"""
Solve The Slot Whisperer challenge.

The server uses an LCG:
  M = 2147483647 (2^31 - 1)
  A = 48271
  C = 12345
  state_{n+1} = (A * state_n + C) % M
  output = state % 100

Strategy: given 10 outputs (state % 100), reconstruct the full state
and predict the next 5.

Approach 1: Bruteforce over k[0] (state[0] = output[0] + 100*k)
For each candidate state[0], generate the sequence and verify that
all outputs match.

M/100 ~= 21.47M candidates, but we can prune quickly:
If state[0] = o[0] + 100*k, then
state[1] = (A * state[0] + C) % M
and state[1] % 100 must equal o[1]

This prunes to ~1/100 of candidates per step.
With 10 outputs, the false positive probability is ~(1/100)^9 ~= 0.
"""

import random
import time
import sys
from pwn import *

context.log_level = 'warn'

HOST = 'chall.0xfun.org'
PORT = 50072

M = 2147483647
A = 48271
C = 12345

def lcg_next(state):
    return (A * state + C) % M

def find_state(outputs):
    """Given a list of outputs (state % 100), find state[0]."""
    o0 = outputs[0]

    # state[0] = o0 + 100*k for k = 0, 1, 2, ...
    # M / 100 = 21474836.47, so k goes from 0 to 21474836
    max_k = M // 100

    for k in range(max_k + 1):
        state = o0 + 100 * k
        if state >= M:
            break

        # Verify against the following outputs
        s = state
        match = True
        for i in range(1, len(outputs)):
            s = lcg_next(s)
            if s % 100 != outputs[i]:
                match = False
                break

        if match:
            return state

    return None

def predict_next(state0, n_observed, n_predict):
    """Given state0, advance n_observed steps and predict n_predict."""
    s = state0
    for _ in range(n_observed):
        s = lcg_next(s)
    predictions = []
    for _ in range(n_predict):
        s = lcg_next(s)
        predictions.append(s % 100)
    return predictions

# ============================================================
# Offline test first
# ============================================================
print("=== Offline test ===")
# Generate test sequence
test_lcg_state = 12345
test_outputs = []
s = test_lcg_state
for _ in range(15):
    s = lcg_next(s)
    test_outputs.append(s % 100)

print(f"Test sequence (seed=12345): {test_outputs[:10]}")
print(f"Next 5: {test_outputs[10:]}")

# Find the state
print("Searching for state...")
t_start = time.time()
found_state = find_state(test_outputs[:10])
t_end = time.time()

if found_state is not None:
    print(f"State found: {found_state} (in {t_end-t_start:.2f}s)")
    # The found_state is state[0] AFTER the first lcg_next
    # So state[0] already has the first next applied
    # To predict, we need to advance 9 more steps (we already have 10 outputs)
    # and then the next 5

    # Recalculate: state[0] corresponds to output[0]
    # state[1] = lcg_next(state[0]) -> output[1]
    # ...
    # state[9] = lcg_next(state[8]) -> output[9]
    # state[10] = lcg_next(state[9]) -> output[10] (prediction 1)
    # ...

    s = found_state
    for i in range(9):
        s = lcg_next(s)
    # s is now state[9]
    pred = []
    for _ in range(5):
        s = lcg_next(s)
        pred.append(s % 100)
    print(f"Prediction: {pred}")
    print(f"Expected:   {test_outputs[10:]}")
    assert pred == test_outputs[10:], "ERROR: incorrect prediction!"
    print("TEST PASSED!")
else:
    print("ERROR: state not found")

# ============================================================
# Now against the real server
# ============================================================
print("\n=== Connecting to server ===")
try:
    p = remote(HOST, PORT)
    data = p.recvuntil(b'separated): ', timeout=10)

    seq = []
    for line in data.decode().strip().split('\n'):
        try:
            val = int(line.strip())
            if 0 <= val <= 99:
                seq.append(val)
        except:
            pass

    print(f"Sequence received: {seq}")

    if len(seq) != 10:
        print(f"ERROR: expected 10 numbers, received {len(seq)}")
        p.close()
        sys.exit(1)

    print("Searching for LCG state...")
    t_start = time.time()
    state0 = find_state(seq)
    t_end = time.time()

    if state0 is not None:
        print(f"State[0] found: {state0} (in {t_end-t_start:.2f}s)")

        # Advance 9 steps to reach state[9]
        s = state0
        for _ in range(9):
            s = lcg_next(s)

        # Predict the next 5
        pred = []
        for _ in range(5):
            s = lcg_next(s)
            pred.append(s % 100)

        print(f"Prediction: {pred}")

        # Send
        pred_str = ' '.join(map(str, pred))
        print(f"Sending: {pred_str}")
        p.sendline(pred_str.encode())

        resp = p.recvall(timeout=10).decode()
        print(f"Server response: {resp}")

        import re
        flags = re.findall(r'0xfun\{[^}]+\}', resp)
        if flags:
            print(f"\n[+] FLAG: {flags[0]}")
        elif 'Wrong' not in resp:
            print(f"\nFull response: {resp}")
    else:
        print("LCG state not found!")
        print("Perhaps the LCG parameters are different on the server")
        p.close()

except Exception as e:
    print(f"Connection error: {e}")
    print("The server may be temporarily unavailable.")
    print("Run again when the service is available.")
