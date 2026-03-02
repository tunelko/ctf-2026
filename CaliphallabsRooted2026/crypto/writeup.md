# Secure Sign

| Field       | Value                            |
|-------------|----------------------------------|
| Platform    | caliphallabsRooted2026           |
| Category    | crypto                           |
| Difficulty  | Easy                             |
| URL         | http://securesign.challs.caliphallabs.com |

## Description
Las librerías criptográficas de ECDSA en Go tienen una API muy rara, así que he creado mi propia implementación de la firma.

http://securesign.challs.caliphallabs.com/

## TL;DR
The `/api/sign` endpoint acts as an **unrestricted signing oracle**: it signs any document we send it with the server's private key. The `/api/verify` endpoint returns the flag if we send it a valid signature whose document is the bytes of the server's public key. Since the signing oracle gives us the public key in each response and signs without restrictions, we just need to sign the public key itself and submit it to verify.

## Initial Analysis

### Project Structure

```
Secure_Sign/
├── challenge/
│   ├── main.go                 # Entry point, routes
│   ├── handlers/
│   │   ├── auth.go             # Register, Login, User
│   │   └── crypto.go           # SignDocument, VerifySignature (VULN HERE)
│   ├── middleware/
│   │   └── auth.go             # JWT middleware
│   ├── models/
│   │   └── user.go             # User model (GORM)
│   ├── database/
│   │   └── connect.go          # SQLite connection
│   ├── utils/
│   │   └── keys.go             # ECDSA P-256 key generation/loading
│   └── public/                 # Frontend (HTML/JS/CSS)
├── Dockerfile                  # Go 1.26 Alpine
├── docker-compose.yml
└── entrypoint.sh               # Sets FLAG and JWT_SECRET
```

### Technology Stack
- **Backend**: Go 1.25.6 with Fiber v2 (web framework)
- **Crypto**: ECDSA on P-256 curve (secp256r1) with custom signing implementation
- **Auth**: JWT (HS256) with bcrypt for passwords
- **DB**: SQLite with GORM
- **Signature format**: ASN.1 DER encoding of (R, S)

### Endpoint Map

| Route | Method | Auth | Description |
|-------|--------|------|-------------|
| `/api/register` | POST | No | User registration |
| `/api/login` | POST | No | Login → JWT token |
| `/api/user` | GET | Yes | User info |
| `/api/sign` | POST | Yes | **Signs documents** (signing oracle) |
| `/api/verify` | POST | No | **Verifies signatures** (returns flag if it's the PK) |

Key note: `/api/verify` **does NOT require authentication** (it's registered before the `IsAuthenticated` middleware in `main.go:29`), while `/api/sign` does.

## Vulnerability Identified

### Logic Flaw: Unrestricted signing oracle + Broken Proof of Possession

The vulnerability is a **design flaw** in the application logic, not in the cryptography.

#### 1. The signing oracle (`/api/sign`) — `handlers/crypto.go:70-124`

```go
func SignDocument(c *fiber.Ctx) error {
    // ...
    for _, file := range req.Files {
        fileBytes, err := base64.StdEncoding.DecodeString(file.Content)
        // ...
        hash := sha256.Sum256(fileBytes)
        priv := utils.GetPrivateKey()
        N := priv.Params().N

        buf := make([]byte, 32)
        reader.Read(buf)           // CustomReader generates nonce k
        k := new(big.Int).SetBytes(buf)
        k.Mod(k, N)

        kGx, _ := priv.Curve.ScalarBaseMult(k.Bytes())
        r := new(big.Int).Mod(kGx, N)
        s := new(big.Int).Mul(
            new(big.Int).ModInverse(k, N),
            new(big.Int).Add(
                new(big.Int).SetBytes(hash[:]),
                new(big.Int).Mul(r, priv.D),    // priv.D = private key
            ),
        )
        s.Mod(s, N)
        // ... returns ASN.1 signature
    }

    pk, _ := utils.GetPublicKey().Bytes()
    return c.JSON(fiber.Map{
        "results":    results,
        "public_key": hex.EncodeToString(pk),   // PK LEAK in hex
    })
}
```

Issues:
1. **Signs any document** without verifying content or blacklists
2. **Exposes the public key** in raw hex format in each response
3. The nonce `k` is generated with a weak `CustomReader` (int16 LCG), but this is irrelevant for the main attack

#### 2. The flag condition (`/api/verify`) — `handlers/crypto.go:188-197`

```go
valid := ecdsa.Verify(publicKey, hash[:], sig.R, sig.S)

// Proof of Possession
if valid && bytes.Equal(docBytes, pk) {
    return c.JSON(fiber.Map{
        "filename": docFile.Filename,
        "valid":    valid,
        "flag":     os.Getenv("FLAG"),    // <--- FLAG
    })
}
```

The flag is returned if:
1. `valid == true` → the ECDSA signature is valid over `sha256(docBytes)` with the server's public key
2. `bytes.Equal(docBytes, pk)` → the signed document is exactly the bytes of the public key

Where `pk, _ := utils.GetPublicKey().Bytes()` — returns the public key in **uncompressed point** format (65 bytes: `0x04 || X || Y`).

#### 3. The attack chain

```
Attacker                              Server
   │                                     │
   │── POST /api/sign (doc=dummy) ──────>│
   │<── {public_key: "0486...", sig} ────│  ← We obtain PK hex
   │                                     │
   │── POST /api/sign (doc=PK_bytes) ───>│
   │<── {sig_of_PK: "3045..."} ─────────│  ← Signature of the PK itself
   │                                     │
   │── POST /api/verify ────────────────>│
   │   (document=PK_bytes, sig=sig_PK)   │
   │<── {flag: "clctf{...}"} ───────────│  ← FLAG
```

The "Proof of Possession" assumes that only whoever possesses the private key can sign the public key. But the server itself is an open signing oracle, so any authenticated user can obtain that signature.

### Vulnerability Type
- **CWE-862**: Missing Authorization — no control over which documents can be signed
- **CWE-290**: Authentication Bypass by Spoofing — the proof of possession is bypassable via the signing oracle itself

### Red herring: CustomReader with weak LCG

The code includes a `CustomReader` (lines 38-59) with a weak PRNG:

```go
type CustomReader struct {
    state  int16       // Only 16 bits of state → 65536 possible values
    random []byte      // 32 random bytes per request
}

var a, c int16 = 31337, 1337    // LCG constants

func (r *CustomReader) Read(p []byte) (n int, err error) {
    var s []byte
    for i := range p {
        if i%2 == 0 {
            r.state = a*r.state + c             // LCG with period ≤ 65536
            s = big.NewInt(int64(r.state)).Bytes()
            p[i] = sha256.Sum256(append(s, r.random...))[i]
        } else {
            p[i] = sha256.Sum256(append(r.random, s...))[i]
        }
    }
    return len(p), nil
}
```

This PRNG has several weaknesses:
- **16-bit state**: the LCG `state = 31337*state + 1337` over int16 has a maximum period of 65536
- **Fixed seed**: `state` always starts at `12345` per request
- **Same random seed per batch**: all documents in a request share the same `random`

This would allow alternative attacks (lattice attack to recover the private key from signatures with related nonces), but the logic flaw makes it unnecessary.

## Solution Process

###  Source code reconnaissance

After extracting `Secure_Sign.zip`, the Go project structure was analyzed:

```bash
unzip -o Secure_Sign.zip -d .
find Secure_Sign -name "*.go" -exec wc -l {} \;
```

6 Go files were identified: `main.go`, `auth.go`, `crypto.go`, `keys.go`, `user.go`, `connect.go`.

The critical file is `handlers/crypto.go` with the `SignDocument` and `VerifySignature` functions.

###  Identifying the objective

In `VerifySignature` (crypto.go:191-196), the flag condition is clear:
- We need a valid ECDSA signature
- Of a document that is exactly `publicKey.Bytes()` (65 bytes, P-256 uncompressed point)

###  Identifying the signing oracle

`SignDocument` (crypto.go:87-119):
- Accepts a JSON array of `{filename, content}` where content is base64
- Signs each one with `sha256(content)` → ECDSA sign with the server's private key
- Returns the signature in ASN.1 DER hex
- **Bonus**: returns `public_key` in hex in the response (line 122-123)

There is no verification of what content is being signed. It is a **pure signing oracle**.

###  Exploitation chain

```python
# 1. Register user
session.post(f"{BASE}/api/register", json={"email": email, "password": password})

# 2. Login → JWT
r = session.post(f"{BASE}/api/login", json={"email": email, "password": password})
token = r.json()["token"]
headers = {"Authorization": f"Bearer {token}"}

# 3. Sign dummy → get public key hex
dummy = base64.b64encode(b"dummy").decode()
r = session.post(f"{BASE}/api/sign",
                 json={"files": [{"filename": "dummy.txt", "content": dummy}]},
                 headers=headers)
pk_hex = r.json()["public_key"]
pk_bytes = bytes.fromhex(pk_hex)   # 65 bytes: 04 || X (32B) || Y (32B)

# 4. Sign the public key as a document
pk_b64 = base64.b64encode(pk_bytes).decode()
r = session.post(f"{BASE}/api/sign",
                 json={"files": [{"filename": "pubkey.bin", "content": pk_b64}]},
                 headers=headers)
sig_hex = r.json()["results"][0]["signature"]

# 5. Verify → flag
r = session.post(f"{BASE}/api/verify",
                 files={"document": ("pubkey.bin", pk_bytes, "application/octet-stream")},
                 data={"signature": sig_hex})
print(r.json()["flag"])
```

###  Execution against remote

```
$ python3 solve.py --remote
[*] Target: http://securesign.challs.caliphallabs.com
[*] Registering...
[*] Register: 500 - {"message":"Could not create user"}   ← already existed
[*] Logging in...
[*] Login: 200
[*] Signing dummy doc to get public key...
[*] Sign status: 200
[+] Public key hex: 0486361ca379b8eb2a1d0aadc290a55e3c2592411a194a4682e123e8c97f27816ba99656a91d440424d05f1b5583f2552d8f055a51aec63d20a476f45d4c997270
[+] Public key length: 65 bytes
[*] Signing public key bytes...
[*] Sign status: 200
[+] Signature: 3045022100e226191f4b756334bd17418473a38b03cf5c517d48ec7d8d9c534c97f66028890220632cb2f9fb935e5dd272dfbdaa886568c4a2f6a069df0964bd29a8ee6ce9d8ff
[*] Submitting to /api/verify for flag...
[*] Verify status: 200
[+] Response: {"filename":"pubkey.bin","flag":"clctf{0tr0_n0nc3_r3us3_3n_3cd5a...}","valid":true}

[+] FLAG: clctf{0tr0_n0nc3_r3us3_3n_3cd5a...}
```

## Discarded Approaches

### Approach A: Attack the CustomReader / ECDSA nonce
The `CustomReader` uses an int16 LCG with a fixed initial `state` (12345) and 32 bytes of `random` per request. Theoretically, with enough signatures from the same request (batch signing), a lattice attack (HNP - Hidden Number Problem) could be mounted to recover the private key. However, the logic flaw makes this approach unnecessary.

### Approach B: Attack the JWT
The JWT uses HS256 with a randomly generated secret (`head -c 64 /dev/urandom | base64`). No algorithm confusion is possible and the secret is not weak. Discarded.

### Approach C: SQLi in login/register
GORM with parameterized queries (`Where("email = ?", data["email"])`). Not vulnerable. Discarded.

## Final Exploit

Complete script in `solve.py`:

```python
#!/usr/bin/env python3
"""
Challenge: Secure Sign
Category:  crypto
Platform:  caliphallabsRooted2026

The /api/sign endpoint signs ANY document we provide and returns the server's
public key hex. The /api/verify gives the flag if we provide a valid signature
of the public key bytes. So: sign the public key itself → submit to verify → flag.
"""
import requests
import sys
import base64

LOCAL_URL = "http://localhost:7000"
REMOTE_URL = "http://securesign.challs.caliphallabs.com"
BASE = REMOTE_URL if "--remote" in sys.argv else LOCAL_URL
session = requests.Session()

def exploit():
    email = "exploit@test.com"
    password = "password123"

    # 1. Register + Login
    session.post(f"{BASE}/api/register", json={"email": email, "password": password})
    r = session.post(f"{BASE}/api/login", json={"email": email, "password": password})
    token = r.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Get public key via signing oracle
    dummy = base64.b64encode(b"dummy").decode()
    r = session.post(f"{BASE}/api/sign",
                     json={"files": [{"filename": "d.txt", "content": dummy}]},
                     headers=headers)
    pk_bytes = bytes.fromhex(r.json()["public_key"])

    # 3. Sign the public key itself
    r = session.post(f"{BASE}/api/sign",
                     json={"files": [{"filename": "pk.bin",
                            "content": base64.b64encode(pk_bytes).decode()}]},
                     headers=headers)
    sig_hex = r.json()["results"][0]["signature"]

    # 4. Verify → flag
    r = session.post(f"{BASE}/api/verify",
                     files={"document": ("pk.bin", pk_bytes)},
                     data={"signature": sig_hex})
    print(r.json())

if __name__ == "__main__":
    exploit()
```

## Execution
```bash
python3 solve.py             # Local (requires docker-compose up)
python3 solve.py --remote    # Remote
```

## Flag
```
clctf{0tr0_n0nc3_r3us3_3n_3cd5a...}
```

## Key Lessons

1. **The cryptography can be correct and the application can still be vulnerable**: the ECDSA implementation (although it uses weak nonces) was not the attack vector. The flaw was purely logical.

2. **A signing oracle must not sign arbitrary data**: if the server signs anything, any "proof of possession" based on signing the public key is trivially bypassable. The correct fix would be one of these:
   - Blacklist: refuse to sign documents that match the public key
   - Commitment scheme: verify should require a challenge-response, not just a static signature
   - Key separation: use different keys for signing user documents vs. for proof of possession

3. **Read ALL the code before attacking the crypto**: the challenge description suggested the bug was in the ECDSA implementation ("I've created my own signature implementation"), but the real bug was more superficial. The weak `CustomReader` was a red herring or a second solution path.

4. **Endpoints without auth can be backdoors**: `/api/verify` does not require authentication (it's before the middleware), which facilitates the attack since we don't even need the token for the final step.

## Additional Technical Details

### Public Key Format

The public key is obtained with `(*ecdsa.PublicKey).ECDH().Bytes()` in Go, which returns the point in **uncompressed** format:

```
04 || X (32 bytes) || Y (32 bytes) = 65 bytes total
```

Example from the server:
```
0486361ca379b8eb2a1d0aadc290a55e3c2592411a194a4682e123e8c97f27816b
a99656a91d440424d05f1b5583f2552d8f055a51aec63d20a476f45d4c997270
```

### ECDSA Signature Format

The signature is encoded in ASN.1 DER (standard for ECDSA):
```
SEQUENCE {
    INTEGER r,
    INTEGER s
}
```

And transmitted as a hex string. Example:
```
3045022100e226191f4b756334bd17418473a38b03cf5c517d48ec7d8d9c534c97
f66028890220632cb2f9fb935e5dd272dfbdaa886568c4a2f6a069df0964bd29a8
ee6ce9d8ff
```

### CustomReader Analysis (alternative path)

If the logic flaw didn't exist, the approach would be:

1. **Sign 2+ documents in a batch**: same `random`, deterministic state from 12345
2. **The LCG has only 65536 possible states**: with two signatures from the same batch, all possible LCG states could be tested
3. **Given k, recover the private key**: `d = (s*k - h) * r^(-1) mod N`
4. **Brute force**: iterate over all 65536 possible initial states, regenerate the nonces, verify against the known signatures

But this was unnecessary thanks to the open signing oracle.

## References
- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- [ECDSA - Wikipedia](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
- [Signing Oracle Attacks](https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/)
- [RFC 6979 - Deterministic Usage of DSA and ECDSA](https://datatracker.ietf.org/doc/html/rfc6979)
