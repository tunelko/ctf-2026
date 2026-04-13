#!/usr/bin/env python3
"""DawgCTF 2026 - Protocol Analysis 6: Sneedham-Chucker — Needham-Schroeder MITM (Lowe attack)"""
import requests

BASE = "https://protocols.live"
H = {"Content-Type": "application/json"}

def util(ep, content):
    r = requests.post(f"{BASE}/util{ep}", headers=H, json={"conn_id": "0", "content": content})
    return r.json()["content"]

def entity(name, cid, content):
    return requests.post(f"{BASE}/{name}", headers=H,
        json={"conn_id": cid, "content": content}).json()["content"]

# Generate our keypair + cert (can't use alice/bob/chuck/sneed)
kp = util("/gen_asym_key_pair", "").split("|")
our_pub, our_priv = kp[1], kp[3]
our_cert = util("/get_cert", f"{our_pub}|n:mallory")

conn_id = requests.post(f"{BASE}/model/6", headers=H).json()["conn_id"]

# 1. Bob (chuck) → pub_B, chuck, cert_B
bob1 = entity("bob", conn_id, "")
pub_B = bob1.split("|")[0]

# 2. Send our identity to Alice (sneed) — she sends {n_A, pub_A, sneed, cert_A}_{pub_X}
alice1 = entity("alice", conn_id, f"{our_pub}|n:mallory|{our_cert}")

# 3. Decrypt with our priv → get n_A, pub_A, sneed, cert_A
dec1 = util("/asym_decrypt", f"{our_priv}|{alice1}")
n_A = dec1.split("|")[0]  # d:nonce_hex

# 4. Re-encrypt for Bob under pub_B
reenc1 = util("/asym_encrypt", f"{pub_B}|t:{dec1}")

# 5. Bob decrypts, sends {n_A, n_B}_{pub_A} — we can't read this
bob2 = entity("bob", conn_id, reenc1)

# 6. Forward to Alice — she decrypts, gets n_B (thinks it's n_X), sends {n_B}_{pub_X}
alice2 = entity("alice", conn_id, bob2)

# 7. Decrypt to recover n_B
n_B = util("/asym_decrypt", f"{our_priv}|{alice2}")

# 8. Re-encrypt n_B for Bob
reenc2 = util("/asym_encrypt", f"{pub_B}|t:{n_B}")

# 9. Bob verifies n_B, sends {FLAG}_{h(n_A+n_B)}
bob3 = entity("bob", conn_id, reenc2)
entity("alice", conn_id, bob3)  # complete protocol

# 10. Decrypt flag: key = h(n_A || n_B), nonce = first 12 bytes of key
n_A_hex = n_A.split(":")[1]
n_B_hex = n_B.split(":")[1]
hash_key = util("/hash_data", f"d:{n_A_hex}{n_B_hex}").split(":")[1]
nonce = hash_key[:24]  # first 12 bytes of hash as nonce
enc_hex = bob3.split(":")[1]

flag = util("/sym_decrypt", f"k:{hash_key}|d:{nonce}|d:{enc_hex}")
print(f"Flag: {flag}")
