#!/usr/bin/env python3
"""DawgCTF 2026 - Protocol Analysis 5: Is This Real? — MITM asymmetric key swap"""
import requests

BASE = "https://protocols.live"
H = {"Content-Type": "application/json"}

conn_id = requests.post(f"{BASE}/model/5", headers=H).json()["conn_id"]

# Generate our own keypair
kp = requests.post(f"{BASE}/util/gen_asym_key_pair", headers=H,
    json={"conn_id": conn_id, "content": ""}).json()["content"]
kp_parts = kp.split("|")
our_pub = kp_parts[1]   # k:PUBHEX
our_priv = kp_parts[3]  # k:PRIVHEX

# Alice sends her pub key with the request
alice_msg = requests.post(f"{BASE}/alice", headers=H,
    json={"conn_id": conn_id, "content": ""}).json()["content"]

# Replace Alice's pub with ours
parts = alice_msg.split("|")
for i, p in enumerate(parts):
    if p.startswith("k:"):
        parts[i] = our_pub
        break
modified = "|".join(parts)

# Bob encrypts FLAG under OUR pub key
bob_msg = requests.post(f"{BASE}/bob", headers=H,
    json={"conn_id": conn_id, "content": modified}).json()["content"]
enc_data = [p for p in bob_msg.split("|") if p.startswith("d:")][0]

# Decrypt with our private key
r = requests.post(f"{BASE}/util/asym_decrypt", headers=H,
    json={"conn_id": "0", "content": f"{our_priv}|{enc_data}"})
print(f"Flag: {r.json()['content']}")
