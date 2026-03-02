# ECB Cut-and-Paste — HackOn CTF 2025 (Crypto)

**Flag:** `HackOn{Typ1c4l_Ch41l3ngE_of_435_3C8_h4h4ha!}`

## Description

> Se nos proporciona un servicio "Token Manager" que permite registrar usuarios y hacer login con un token de sesión. El objetivo es obtener `role=admin` para que el servidor nos entregue la flag.

## Code Analysis

```python
KEY = os.urandom(16)
SECRET_PREFIX = os.urandom(secrets.randbelow(14) + 1)  # 1-14 bytes random

def register():
    email = input("Introduce tu email: ").replace("\n", "")
    if "&" in email or "=" in email:
        print("Caracteres prohibidos detectados.")
        return
    profile_content = f"email={email}&uid={uid}&role=user".encode()
    plaintext = SECRET_PREFIX + profile_content
    token = aes_ecb_encrypt(plaintext)  # AES-128-ECB + PKCS7

def login():
    # Decrypts token, strips prefix, parses key=value, checks role=admin
```

Key points:
- **AES in ECB mode**: each 16-byte block is encrypted independently
- **SECRET_PREFIX**: random 1-14 bytes prepended to plaintext
- Email cannot contain `&` or `=`, but arbitrary bytes are allowed
- Profile is parsed with `split("&")` and `split("=")` → we need `role=admin`

## Vulnerability

ECB encrypts each 16-byte block independently. This allows **cutting** encrypted blocks from one token and **pasting** them into another to construct an arbitrary plaintext.

## Strategy

### 1. Determine PREFIX length

We register emails of increasing length (L=0,1,2,...) and observe when the ciphertext grows by 16 bytes (one block). The jump occurs when:

```
(P + 23 + L) ≡ 0 (mod 16)
```

Where `P` = prefix length, `23 = len("email=") + len("&uid=") + 2 + len("&role=user")`.

Solving: `P = (-(23 + L_jump)) mod 16`

In our case: jump at L=11 → **P = 14**.

### 2. Create "admin" block with valid PKCS7 padding

We need an encrypted block containing exactly:

```
admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b  (5 + 11 = 16 bytes)
```

This is valid PKCS7 for the string "admin". We register an email that aligns `admin\x0b*11` to a block boundary:

```
offset = P + len("email=") + pad_A = P + 6 + pad_A ≡ 0 (mod 16)
pad_A = (16 - (P + 6) % 16) % 16 = 12
```

Email: `"A"*12 + "admin" + "\x0b"*11`

### 3. Create token where `&role=` ends at block boundary

```
length until "&role=" = P + 6 + pad_B + 5 + D + 6 = P + 17 + D + pad_B
pad_B = (16 - (P + 17 + D) % 16) % 16 = 15
```

Email: `"B"*15`

Resulting plaintext:
```
[PREFIX 14B] email=BBBBBBBBBBBBBBB | &uid=24&role=    | user + padding
             ← block 0 →           ← block 1 →       ← block 2 →       ← block 3 →
```

### 4. Cut and paste

From the "role" token: take blocks 0-2 (everything up to `&role=`)
From the "admin" token: take block 2 (`admin\x0b*11`)

```
token_crafted = role_blocks[0:3] + admin_block
```

After decryption and prefix removal:
```
email=BBBBBBBBBBBBBBB&uid=24&role=admin
```

→ `role=admin` → **FLAG**

## Exploit

```python
#!/usr/bin/env python3
from pwn import *

HOST = "0.cloud.chals.io"
PORT = 28210

def register(r, email_bytes):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"email: ", email_bytes)
    r.recvuntil(b"generado: ")
    return r.recvline().strip().decode()

def login(r, token_hex):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"(hex): ", token_hex.encode())

r = remote(HOST, PORT)

# Phase 1: Determine PREFIX length
prev_len = None
uid_counter = 11
for l in range(0, 17):
    tok = register(r, b"A" * l)
    uid_counter += 1
    D = len(str(uid_counter - 1))
    if prev_len is not None and len(tok) != prev_len:
        P = (-(21 + D + l)) % 16
        break
    prev_len = len(tok)

# Phase 2: Calculate alignments
D_role = len(str(uid_counter + 1))
pad_A = (16 - (P + 6) % 16) % 16
pad_B = (16 - (P + 17 + D_role) % 16) % 16

# Phase 3: Register crafted emails
tok_admin = register(r, b"A" * pad_A + b"admin" + b"\x0b" * 11)
uid_counter += 1
tok_role = register(r, b"B" * pad_B)
uid_counter += 1

# Phase 4: Cut and paste
admin_idx = (P + 6 + pad_A) // 16
admin_hex = tok_admin[admin_idx * 32 : (admin_idx + 1) * 32]

role_end = P + 17 + D_role + pad_B
role_hex = tok_role[:role_end // 16 * 32]

crafted = role_hex + admin_hex

# Login
login(r, crafted)
print(r.recvall(timeout=5).decode())
r.close()
```

```
$ python3 exploit_ecb.py
Sesion decodificada: email=BBBBBBBBBBBBBBB&uid=24&role=admin
ROL ADMIN CONFIRMADO, AQUI TIENES TU FLAG: HackOn{Typ1c4l_Ch41l3ngE_of_435_3C8_h4h4ha!}
```
