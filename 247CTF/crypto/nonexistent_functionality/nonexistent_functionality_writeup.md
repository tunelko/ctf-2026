# Missing Encryption - Padding Oracle Attack Writeup

## Challenge Description
We ran out of time to implement encryption for our cipher. Can you abuse the decryption implementation to recover the flag?

## Analysis

### The Vulnerable Code
```python
class Padding:
    def unpad(self, s):
        self.is_valid_padding(s)
        return s[ord(s[0]):]

    def is_valid_padding(self, s):
        padding_length = ord(s[0])
        if padding_length == 0: raise Exception('Invalid padding')
        for i in range(padding_length):
            if ord(s[i]) != padding_length:
                raise Exception('Invalid padding')

class AESCipher:
    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.padding.unpad(cipher.decrypt(enc[AES.block_size:]))
```

### The Vulnerability: Padding Oracle
The server responds differently based on padding validity:
- **"Something went wrong!"** - Invalid padding (exception raised)
- **"Invalid password!"** - Valid padding, wrong password

This is a classic **Padding Oracle Attack** vulnerability!

### Custom Padding Scheme
The padding is **reversed PKCS7** - padding bytes are **prepended**, not appended:
```
"secret_admin_password" (21 bytes) + 11 bytes padding =
"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0bsecret_admin_password" (32 bytes)
```

## The Attack

### How Padding Oracle Works
In AES-CBC:
```
Plaintext[i] = Decrypt(Ciphertext[i]) XOR IV[i]  (or XOR Ciphertext[i-1])
```

By manipulating the IV, we can control what the decrypted plaintext looks like. The oracle tells us if our manipulation produced valid padding.

### Target
We need to forge ciphertext that decrypts to:
- **Block 1**: `\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0bsecre` (16 bytes)
- **Block 2**: `t_admin_password` (16 bytes)

### Attack Phases

#### Phase 1: Find Pre-XOR Values for Block 1
With C1 = zeros, brute-force IV bytes to find what makes valid padding:
- Byte 0: Find IV[0] where decrypt gives `\x01` in first position
- Byte 1: Find IV[1] where decrypt gives `\x02\x02` in first two positions
- Continue for all 16 bytes

```
Pre-XOR block 1: dc36f147a01e5d911633981ac0364f54
```

#### Phase 2: Find Pre-XOR Values for Block 2
Calculate C1 that gives us "t_admin_password" in block 2:
```
C1[i] = PreXOR1[i] XOR "t_admin_password"[i]
```

Then repeat the oracle attack with this fixed C1 to find PreXOR2.

```
C1 for block 2: a8699023cd7733ce6652eb69b7593d30
Pre-XOR block 2: d3e744bebbc395a903de61c22b1c0783
```

#### Phase 3: Craft Final Payload
Calculate IV that produces our target first block:
```
IV[i] = PreXOR_new[i] XOR "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0bsecre"[i]
```

Final payload structure: `IV (16) + C1_fixed (16) + C2_zeros (16)`

## Solution

```python
from base64 import b64encode
import requests

URL = "https://1ea5b729c6308626.247ctf.com/get_flag"

# Pre-computed values from oracle attack
prexor1 = bytes.fromhex("dc36f147a01e5d911633981ac0364f54")
prexor2 = bytes.fromhex("d3e744bebbc395a903de61c22b1c0783")

# C1 that gives "t_admin_password" in block 2
target_block2 = b"t_admin_password"
c1_fixed = bytes([prexor1[i] ^ target_block2[i] for i in range(16)])

# IV that gives "\x0b"*11 + "secre" in block 1
target_block1 = b"\x0b" * 11 + b"secre"
iv = bytes([prexor2[i] ^ target_block1[i] for i in range(16)])

# Final payload
payload = iv + c1_fixed + bytes(16)
encoded = b64encode(payload).decode()

# Get flag
resp = requests.get(URL, params={'password': encoded})
print(resp.text)
```

## Flag
```
247CTF{b85396dfXXXXXXXXXXXXXXXXb2118269}
```

## Lessons Learned

1. **Padding Oracle Attack**: Different error messages reveal padding validity
2. **CBC Malleability**: We can control decrypted plaintext by manipulating IV/ciphertext
3. **Pre-XOR Values**: The intermediate state `Decrypt(C)` before XOR with IV
4. **Byte-by-byte Recovery**: Find each byte by making the oracle accept padding

## Prevention
- Use authenticated encryption (AES-GCM)
- Return the same error message for all failures
- Use constant-time comparison functions
