#!/usr/bin/env python3
"""DawgCTF 2026 - Protocol Analysis 4: Real Security! — Intercept symmetric key"""
import requests

BASE = "https://protocols.live"
H = {"Content-Type": "application/json"}

conn_id = requests.post(f"{BASE}/model/4", headers=H).json()["conn_id"]

# Alice sends message with symmetric key k and nonce n in plaintext
alice_msg = requests.post(f"{BASE}/alice", headers=H,
    json={"conn_id": conn_id, "content": ""}).json()["content"]

# Extract key and nonce
parts = alice_msg.split("|")
key = [p for p in parts if p.startswith("k:")][0]
nonce = [p for p in parts if p.startswith("d:")][0]

# Forward to Bob — he encrypts FLAG with the key
bob_msg = requests.post(f"{BASE}/bob", headers=H,
    json={"conn_id": conn_id, "content": alice_msg}).json()["content"]
enc_data = [p for p in bob_msg.split("|") if p.startswith("d:")][0]

# Decrypt with intercepted key using /util/sym_decrypt
r = requests.post(f"{BASE}/util/sym_decrypt", headers=H,
    json={"conn_id": conn_id, "content": f"{key}|{nonce}|{enc_data}"})
print(f"Flag: {r.json()['content']}")

requests.post(f"{BASE}/alice", headers=H,
    json={"conn_id": conn_id, "content": bob_msg})
