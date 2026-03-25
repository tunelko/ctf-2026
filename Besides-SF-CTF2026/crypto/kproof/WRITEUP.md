# kproof — BSidesSF CTF 2026

| Field | Value |
|-------|-------|
| **Category** | Crypto |
| **Points** | 1000 |
| **Author** | symmetric |
| **Flag** | `CTF{truly_marvelous_proof}` |

## Description

> I have a flag and I can prove it. No, you can't see it yet, I'll reveal it later!

We're given a web terminal to a service on port 3649 and a `flag.pcap` capture file.

## TL;DR

The server implements a Goldwasser-Micali (GM) based "proof of knowledge" commitment system. The `submit-k` command acts as a **decryption oracle** — by submitting 128 carefully crafted queries (one per AES key bit), we recover the full AES-128 key used to encrypt `flag.jpg` in the pcap, then decrypt it.

## Analysis

### The Service

KProof is a commitment tool: you encrypt data with AES-128-CBC, encrypt the AES key bit-by-bit using Goldwasser-Micali, and submit both. The server decrypts everything, SHA-256 hashes the plaintext, and issues a signed commitment certificate containing that hash.

Commands:
- `pubkey` — returns GM public parameters (n, e, x)
- `submit-k` — submit encrypted knowledge (GM-encrypted AES key + AES-CBC ciphertext)
- `validate-k` — validate a commitment certificate

### The PCAP

The capture shows a complete `submit-k` session:

1. **128 GM ciphertexts** — one per bit of the AES-128 key (MSB first)
2. **IV**: `35411baed184ad9d9890a89077f732cc`
3. **Plaintext length**: 298889 bytes
4. **Base64-encoded AES-CBC ciphertext** of `flag.jpg`

The server responded with a commitment certificate confirming:
- Knowledge: `flag.jpg`
- SHA-256: `23d7fbebd58e9280d09dca76676961acc8668e6f5d91b0dde58235c4273b52a5`

### Goldwasser-Micali Encryption

GM encrypts one bit at a time:
- **Public**: n (2048-bit RSA modulus), x (quadratic non-residue mod p and mod q)
- **Encrypt bit b**: choose random y, output `c = x^b * y^2 mod n`
  - b=0: `c = y^2 mod n` (quadratic residue)
  - b=1: `c = x * y^2 mod n` (quadratic non-residue)
- **Decrypt**: compute Jacobi(c, p) and Jacobi(c, q) — both +1 means b=0, both -1 means b=1

Without knowing the factorization of n, GM is semantically secure (QRA assumption). The 2048-bit n is not factorable by standard methods (confirmed via factordb and Pollard's p-1).

## Vulnerability — Decryption Oracle (CWE-200)

The `submit-k` command lets us submit **arbitrary** GM ciphertexts. The server:
1. Decrypts the 128 GM ciphertexts to recover a 128-bit AES key
2. Decrypts our AES-CBC ciphertext with that key
3. Returns `SHA-256(plaintext)` in the commitment certificate

This is a **chosen-ciphertext decryption oracle**. We can determine any single GM bit by observing the resulting hash.

## Exploitation

### Strategy: Bit-by-bit Key Recovery

For each bit position `i` (0–127):
1. Construct 128 GM ciphertexts where:
   - 127 positions: fresh encryptions of **0** (c = y² mod n)
   - Position `i`: the **original** GM ciphertext from the pcap
2. Submit with a known AES-CBC ciphertext (plaintext "AAAAAAAAAAAAAAAA" encrypted under the all-zeros key)
3. The server decrypts GM → AES key has bit `i` as unknown, all others 0
4. Two possible keys → two possible SHA-256 hashes (pre-computed)
5. Compare server's hash to determine bit `i`

### Pre-computation

Before querying, compute both possible hashes for each bit position:
- `hash_0`: SHA-256 of AES-CBC decryption with all-zeros key
- `hash_1[i]`: SHA-256 of AES-CBC decryption with only bit `i` set

### Oracle Queries

128 sequential connections, each taking ~2-3 seconds. Total runtime: ~6 minutes.

### Result

```
Key bits: 11011100011110100000011010010110001010110100111010010100000010010110000011001111100101001010001001000011010110001110110101011100
AES key:  dc7a06962b4e940960cf94a24358ed5c
```

### Decryption

```python
from Crypto.Cipher import AES
key = bytes.fromhex("dc7a06962b4e940960cf94a24358ed5c")
iv  = bytes.fromhex("35411baed184ad9d9890a89077f732cc")
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(aes_ciphertext)[:298889]
# SHA-256 matches: 23d7fbebd58e9280d09dca76676961acc8668e6f5d91b0dde58235c4273b52a5
```

The decrypted `flag.jpg` shows a page from Fermat's *Arithmeticorum Liber VI* — the page with his famous "Last Theorem" marginal note about having a "truly marvelous proof."

## Exploit Code

```python
import socket, time, hashlib, json, base64, random, re, sys
from Crypto.Cipher import AES

HOST = "kproof-f5de3a0e.challenges.bsidessf.net"
PORT = 3649

# Load extracted data from pcap
with open("extracted.json") as f:
    data = json.load(f)

n = int(data["n"], 16)
x = int(data["x"], 16)
original_gm = data["gm_ciphertexts"]

def connect_and_get_hash(gm_key_lines, iv_hex, plaintext):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    sock.connect((HOST, PORT))
    time.sleep(1)
    sock.recv(4096)

    sock.send(b"submit-k\n")
    time.sleep(0.5); sock.recv(4096)
    sock.send(b"test\n")
    time.sleep(0.3); sock.recv(4096)

    sock.send(("\n".join(gm_key_lines) + "\n").encode())
    time.sleep(0.5); sock.recv(16384)

    sock.send((iv_hex + "\n").encode())
    time.sleep(0.3); sock.recv(4096)
    sock.send(f"{len(plaintext)}\n".encode())
    time.sleep(0.3); sock.recv(4096)

    # Encrypt plaintext with all-zeros key
    cipher = AES.new(b'\x00'*16, AES.MODE_CBC, bytes.fromhex(iv_hex))
    ct_b64 = base64.b64encode(cipher.encrypt(plaintext)).decode()
    sock.send((ct_b64 + "\n\n").encode())
    time.sleep(2)

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

iv_hex = "00000000000000000000000000000000"
plaintext = b"A" * 16

# Pre-compute expected hashes
hash_key0 = hashlib.sha256(plaintext).hexdigest()
single_bit_hashes = {}
for i in range(128):
    key_bytes = (1 << (127 - i)).to_bytes(16, 'big')
    ct = AES.new(b'\x00'*16, AES.MODE_CBC, b'\x00'*16).encrypt(plaintext)
    dec = AES.new(key_bytes, AES.MODE_CBC, b'\x00'*16).decrypt(ct)
    single_bit_hashes[i] = hashlib.sha256(dec).hexdigest()

# Pre-generate GM encryptions of 0
zero_gm = []
for i in range(128):
    y = random.randint(2, n-1)
    zero_gm.append(f"0x{pow(y, 2, n):x}")

# Recover each bit
bits = []
for i in range(128):
    gm_lines = list(zero_gm)
    gm_lines[i] = original_gm[i]  # original ciphertext for bit i
    h = connect_and_get_hash(gm_lines, iv_hex, plaintext)
    bits.append(0 if h == hash_key0 else 1)
    print(bits[-1], end='', flush=True)
    time.sleep(0.2)

# Reconstruct key and decrypt flag
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
```

## Key Takeaways

- **GM is IND-CPA secure but NOT IND-CCA2**: the `submit-k` oracle breaks it because the server decrypts arbitrary ciphertexts and leaks the plaintext hash
- **Bit-by-bit recovery**: since GM encrypts each bit independently, we can isolate and determine each bit with a single oracle query
- **Same n for RSA signing and GM encryption**: sharing the modulus between two different schemes (RSA signatures + GM encryption) doesn't directly cause the vulnerability here, but it's generally bad practice
- The flag references Fermat's Last Theorem — "I have a truly marvelous proof of this proposition that this margin is too narrow to contain" — a perfect fit for a proof-of-knowledge challenge

## Files

- `flag.pcap` — provided capture
- `extracted.json` — parsed protocol data from pcap
- `aes_ciphertext.bin` — extracted AES-CBC ciphertext
- `flag.jpg` — decrypted flag image
- `flag.txt` — `CTF{truly_marvelous_proof}`
