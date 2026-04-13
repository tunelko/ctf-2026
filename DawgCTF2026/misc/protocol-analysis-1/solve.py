#!/usr/bin/env python3
"""DawgCTF 2026 - Protocol Analysis 1: Can You Hear Me? — Simple relay"""
import requests

BASE = "https://protocols.live"
H = {"Content-Type": "application/json"}

# Create instance
conn_id = requests.post(f"{BASE}/model/1", headers=H).json()["conn_id"]

# Alice sends → forward to Bob → Bob replies with flag → forward to Alice
alice_msg = requests.post(f"{BASE}/alice", headers=H,
    json={"conn_id": conn_id, "content": ""}).json()["content"]
print(f"Alice: {alice_msg}")

bob_msg = requests.post(f"{BASE}/bob", headers=H,
    json={"conn_id": conn_id, "content": alice_msg}).json()["content"]
print(f"Bob: {bob_msg}")

# Flag is in Bob's response
requests.post(f"{BASE}/alice", headers=H,
    json={"conn_id": conn_id, "content": bob_msg})
