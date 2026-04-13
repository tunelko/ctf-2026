#!/usr/bin/env python3
"""DawgCTF 2026 - Cheater Cheater (rev) - AES decrypt from Pac-Man game"""
from Crypto.Cipher import AES
import base64

# When score hits 6942069, parent.getName() = "6942069"
# val = ((6942069 * 10) + 1) ^ 4 = 69420691^4
val = 69420691 ** 4
val_str = str(val)  # "23225000336468054454242927385361"
rev_str = val_str[::-1]

def hex_to_bytes(s):
    return bytes(int(s[i:i+2], 16) for i in range(0, len(s)-1, 2)
                 if all(c in '0123456789abcdefABCDEF' for c in s[i:i+2]))

aes_key = hex_to_bytes(val_str)  # SecretKeySpec(three, "AES")
iv = hex_to_bytes(rev_str)       # IvParameterSpec(key)

ct = base64.b64decode("6Ach6HiD0JmCc1L+RwxDRzhW3sC1kS6XydgSuWVFpxVXRU8EjfuMxIMoIzMwK/ii")
cipher = AES.new(aes_key[:16], AES.MODE_CBC, iv[:16])
pt = cipher.decrypt(ct)
flag = pt[:-pt[-1]].decode()
print(f"Flag: {flag}")
