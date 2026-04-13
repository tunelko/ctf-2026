# The Eaze-y Way Out — VishwaCTF 2026 (Crypto)

## TL;DR

Atbash cipher (alphabet mirror) followed by Vigenère decryption with key "eaze".

## Analysis

- Ciphertext: `AriozzYCQ{Vawr_Xjxggmpezlox}`
- "Look at it through a mirror" → Atbash cipher (A↔Z, B↔Y, ...)
- "Remember the secret word" → Vigenère key
- "Secret word in the challenge name" → **eaze** (from "The Eaze-y Way Out")

## Solution

```python
def atbash(text):
    result = ''
    for c in text:
        if c.isupper(): result += chr(ord('Z') - ord(c) + ord('A'))
        elif c.islower(): result += chr(ord('z') - ord(c) + ord('a'))
        else: result += c
    return result

def vigenere_decrypt(cipher, key):
    result, ki = '', 0
    for c in cipher:
        if c.isalpha():
            k = ord(key[ki % len(key)].upper()) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result += chr((ord(c) - base - k) % 26 + base)
            ki += 1
        else:
            result += c
    return result

cipher = "AriozzYCQ{Vawr_Xjxggmpezlox}"
step1 = atbash(cipher)        # "ZirlaaBXJ{Ezdi_Cqcttnkvaolc}"
flag = vigenere_decrypt(step1, "eaze")
print(flag)
```

## Flag

```
VishwaCTF{Eaze_Cryptography}
```
