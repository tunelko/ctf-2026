#!/usr/bin/env python3
"""DawgCTF 2026 - Protocol Analysis 2: Liar — Name spoofing"""
import requests

BASE = "https://protocols.live"
H = {"Content-Type": "application/json"}

conn_id = requests.post(f"{BASE}/model/2", headers=H).json()["conn_id"]

# Alice sends with her name
alice_msg = requests.post(f"{BASE}/alice", headers=H,
    json={"conn_id": conn_id, "content": ""}).json()["content"]

# Bob only gives flag to charlie — swap alice→charlie
modified = alice_msg.replace("n:alice", "n:charlie")

bob_msg = requests.post(f"{BASE}/bob", headers=H,
    json={"conn_id": conn_id, "content": modified}).json()["content"]
print(f"Flag: {bob_msg}")

requests.post(f"{BASE}/alice", headers=H,
    json={"conn_id": conn_id, "content": bob_msg})
