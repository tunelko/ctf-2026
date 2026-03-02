# Whisper - Orbital Relay

| Field | Value |
|-------|-------|
| **CTF** | UniVsThreats26Quals |
| **Category** | Mobile |
| **Target** | `http://194.102.62.175:20256` |
| **Flag** | `UVT{1a25b4cdcf840068a67d7cd556020c3bd7149e9848be5603ba06fddcef1a258e}` |

## Challenge Description

> Something in the local signal path is leaking more than it should. Capture the right artifact, authenticate to the relay endpoint, and retrieve the flag.

**Provided:** Android APK (Whisper app)

---

## Step 1 — APK Reconnaissance

```
com.whisper.app/
├── AndroidManifest.xml     # Socket.IO chat app, cleartext to 10.0.2.2
├── classes.dex             # MainActivity, SecurityGuard, MagicMarker
├── lib/*/libwhisper_crypto.so  # Native crypto (HMAC-SHA256 + XOR)
└── res/                    # "ORBITAL RELAY - SECURE ALERT CHANNEL"
```

Key classes (jadx decompilation):
- **MainActivity**: Connects via Socket.IO, receives `session_bundle` event, decrypts it with native `decryptSessionBundle()`, verifies auth via native `computeAuthToken()`
- **SecurityGuard**: Anti-debug/anti-Frida checks (irrelevant for static analysis)

### The "Leak" — Unprotected Broadcast

```java
// MainActivity.java line 101 — sends session data to ANY app
Intent intent = new Intent("com.whisper.app.NOTIFICATION_SYNC");
intent.putExtra("session_id", ...);
intent.putExtra("auth_token", ...);
sendBroadcast(intent);  // No permission! Any app can intercept
```

This is the "local signal path leaking" — the broadcast receiver is **unprotected**, leaking `session_id` and `auth_token` to any listening app.

---

## Step 2 — Native Library Reverse Engineering

### libwhisper_crypto.so (radare2 analysis, x86_64 variant)

**Functions:**
| Address | Name | Purpose |
|---------|------|---------|
| `0xcb0` | `.init_array` constructor | Copies HMAC key to BSS |
| `0xcd0` | `decryptSessionBundle` | hex_decode + XOR decrypt |
| `0x1360` | `computeAuthToken` | HMAC-SHA256 |
| `0x1670` | internal | SHA256 update |
| `0x1940` | internal | SHA256 finalize |

### Init Constructor (0xcb0) — HMAC Key Extraction

```asm
movaps xmm0, [0x7b0]       ; "NobodyExpectsThe" (16 bytes)
movaps [0x3d90], xmm0      ; → BSS[0:16]
movaps xmm0, [0x7d0]       ; "SpainishInquisit" (16 bytes)
movaps [0x3da0], xmm0      ; → BSS[16:32]
ret
```

**HMAC key = `NobodyExpectsTheSpainishInquisit`** (32 bytes, note intentional typo "Spainish")

### decryptSessionBundle (0xcd0)

1. `GetStringUTFChars()` — get hex string from Java
2. SIMD hex-to-binary conversion (vectorized `"0-9a-f"` → nibbles)
3. **XOR decrypt** with 32-byte HMAC key (LOAD2 segment = BSS key)
4. Return decrypted string via `NewStringUTF()`

The XOR loop at `0x11e0`:
```asm
movdqa xmm0, [segment.LOAD2]      ; key[0:16] = "NobodyExpectsThe"
movdqa xmm1, [0x3da0]             ; key[16:32] = "SpainishInquisit"
loop:
    movdqu xmm2, [r13 + rsi]      ; hex_decoded[i:i+16]
    movdqu xmm3, [r13 + rsi + 16] ; hex_decoded[i+16:i+32]
    pxor   xmm2, xmm0             ; XOR with key[0:16]
    pxor   xmm3, xmm1             ; XOR with key[16:32]
    movdqu [rbx + rsi], xmm2      ; store result
    movdqu [rbx + rsi + 16], xmm3
```

### computeAuthToken (0x1360)

Standard HMAC-SHA256 implementation:
1. Build ipad (0x36 * 64) and opad (0x5c * 64), XOR with key bytes from BSS
2. SHA256(ipad || message) → inner hash
3. SHA256(opad || inner_hash) → HMAC result
4. Convert 32-byte hash to 64-char hex string using `"0123456789abcdef"` lookup

**`computeAuthToken(session_id) = HMAC-SHA256("NobodyExpectsTheSpainishInquisit", session_id)`**

---

## Step 3 — Exploitation

### Python Reimplementation

```python
HMAC_KEY = b"NobodyExpectsTheSpainishInquisit"

def decrypt_session_bundle(encrypted_hex):
    raw = bytes.fromhex(encrypted_hex)
    return bytes(raw[i] ^ HMAC_KEY[i % 32] for i in range(len(raw)))

def compute_auth_token(session_id):
    return hmac.new(HMAC_KEY, session_id.encode(), hashlib.sha256).hexdigest()
```

### Attack Flow

1. Connect to `http://194.102.62.175:20256` via Socket.IO (polling transport)
2. Receive `session_bundle` event: `{"encrypted": "<hex>", "length": 181}`
3. Decrypt: `hex_decode(encrypted) XOR key` → JSON: `{"session_id": "...", "auth_token": "..."}`
4. Verify: `compute_auth_token(session_id) == auth_token` ✓
5. Authenticate: `GET /api/flag?token=<auth_token>` → **200 OK + flag**

### Endpoint Discovery

```
GET /api/flag → 401 {"error":"Missing token parameter"}
GET /api/flag?token=<auth_token> → 200 {"flag":"UVT{...}", "message":"Access granted. The broadcast was whispering secrets."}
```

---

## Scripts

- `solve.py` — Full automated exploit (Socket.IO connect → decrypt → auth → flag)

## Key Lessons

1. **Unprotected Android broadcasts** are a classic mobile vuln — `sendBroadcast()` without a permission allows any app to intercept sensitive data (session tokens, auth tokens)
2. **Hardcoded crypto keys in native libs** are extractable — even stripped `.so` files reveal keys through static analysis of `.rodata` and `.init_array` constructors
3. **XOR + HMAC is not encryption** — the "encryption" was just XOR with the HMAC key, making the key serve double duty and trivially recoverable
4. **`.init_array` constructors** run before JNI_OnLoad and can initialize global state (BSS) that's invisible to simple `strings` analysis — always check relocations
5. **The server message says it all**: *"The broadcast was whispering secrets"* — the vuln is the unprotected broadcast leaking auth tokens
