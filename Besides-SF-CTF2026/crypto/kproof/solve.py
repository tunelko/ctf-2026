#!/usr/bin/env python3
"""kproof solver — Goldwasser-Micali decryption oracle via submit-k"""
import socket, time, hashlib, json, base64, re, sys
from Crypto.Cipher import AES

HOST = "kproof-f5de3a0e.challenges.bsidessf.net"
PORT = 3649
PCAP_EXTRACTED = "extracted.json"  # Pre-parsed from flag.pcap

def connect_and_get_hash(gm_key_lines, iv_hex, plaintext):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    sock.connect((HOST, PORT))
    time.sleep(1); sock.recv(4096)
    sock.send(b"submit-k\n"); time.sleep(0.5); sock.recv(4096)
    sock.send(b"test\n"); time.sleep(0.3); sock.recv(4096)
    sock.send(("\n".join(gm_key_lines) + "\n").encode())
    time.sleep(0.5); sock.recv(16384)
    sock.send((iv_hex + "\n").encode()); time.sleep(0.3); sock.recv(4096)
    sock.send(f"{len(plaintext)}\n".encode()); time.sleep(0.3); sock.recv(4096)
    cipher = AES.new(b'\x00'*16, AES.MODE_CBC, bytes.fromhex(iv_hex))
    ct_b64 = base64.b64encode(cipher.encrypt(plaintext)).decode()
    sock.send((ct_b64 + "\n\n").encode()); time.sleep(2)
    response = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk: break
            response += chunk
        except socket.timeout: break
    sock.close()
    m = re.search(r'hash\s*\n?([0-9a-f]{64})', response.decode(errors='replace'))
    return m.group(1) if m else None

def main():
    import random
    with open(PCAP_EXTRACTED) as f:
        data = json.load(f)
    n = int(data["n"], 16)
    original_gm = data["gm_ciphertexts"]

    iv_hex = "00000000000000000000000000000000"
    pt = b"A" * 16

    # Pre-compute hashes for bit=0 and bit=1 at each position
    hash_key0 = hashlib.sha256(pt).hexdigest()
    single_bit_hashes = {}
    for i in range(128):
        key_bytes = (1 << (127 - i)).to_bytes(16, 'big')
        ct = AES.new(b'\x00'*16, AES.MODE_CBC, b'\x00'*16).encrypt(pt)
        dec = AES.new(key_bytes, AES.MODE_CBC, b'\x00'*16).decrypt(ct)
        single_bit_hashes[i] = hashlib.sha256(dec).hexdigest()

    # Pre-generate GM encryptions of 0
    zero_gm = []
    for i in range(128):
        y = random.randint(2, n-1)
        zero_gm.append(f"0x{pow(y, 2, n):x}")

    # Recover each bit via oracle
    bits = []
    for i in range(128):
        gm_lines = list(zero_gm)
        gm_lines[i] = original_gm[i]
        h = connect_and_get_hash(gm_lines, iv_hex, pt)
        bits.append(0 if h == hash_key0 else 1)
        sys.stdout.write(str(bits[-1])); sys.stdout.flush()
        time.sleep(0.2)

    # Reconstruct key and decrypt
    key_int = int(''.join(map(str, bits)), 2)
    key_bytes = key_int.to_bytes(16, 'big')
    print(f"\nAES key: {key_bytes.hex()}")

    with open("aes_ciphertext.bin", "rb") as f:
        aes_ct = f.read()
    iv = bytes.fromhex(data["iv"])
    flag_data = AES.new(key_bytes, AES.MODE_CBC, iv).decrypt(aes_ct)[:data["plaintext_length"]]
    with open("flag.jpg", "wb") as f:
        f.write(flag_data)
    print(f"SHA-256: {hashlib.sha256(flag_data).hexdigest()}")
    print(f"Saved flag.jpg ({len(flag_data)} bytes)")

if __name__ == "__main__":
    main()
