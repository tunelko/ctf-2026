#!/usr/bin/env python3
"""DawgCTF 2026 - Protocol Analysis 3: Missing — Impersonate absent Alice"""
import requests

BASE = "https://protocols.live"
H = {"Content-Type": "application/json"}

conn_id = requests.post(f"{BASE}/model/3", headers=H).json()["conn_id"]

# Alice is gone — send her message directly to Bob
msg = "t:Hello|n:bob|t:this is|n:alice|t:give me the flag"
bob_msg = requests.post(f"{BASE}/bob", headers=H,
    json={"conn_id": conn_id, "content": msg}).json()["content"]
print(f"Flag: {bob_msg}")
