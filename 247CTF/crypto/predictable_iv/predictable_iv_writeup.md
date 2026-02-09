# Predictable IV - AES-CBC Challenge Writeup

## Challenge Description
We are trying to save time by limiting our calls to random. Can you abuse the predictable encryption mechanism to recover the flag?

## Analysis

### The Cipher
The server uses AES-CBC encryption with a critical vulnerability:
- The IV for each encryption is the **last 16 bytes of the previous ciphertext**
- This makes the IV predictable after the first encryption

```python
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(self.pad(raw + flag))
session["IV"] = encrypted[-AES.block_size:]  # Predictable!
```

### Vulnerability: BEAST Attack
This is the **Browser Exploit Against SSL/TLS (BEAST)** attack. In AES-CBC:
- Block encryption: `C[i] = E(P[i] XOR IV)` for first block
- The IV is XORed with plaintext before encryption

Since we:
1. Control the plaintext
2. Know the IV (from previous ciphertext)
3. Can compare ciphertext blocks

We can perform a **byte-at-a-time** chosen plaintext attack.

## Exploitation

### Method 1: First 16 Bytes

1. Send 31 bytes of padding so 1 flag byte enters block 2
2. XOR our first block with the known IV to "nullify" the IV effect
3. For each guess, compare the ciphertext of block 2
4. When ciphertexts match, we found the correct flag byte
5. Reduce padding by 1 and repeat

```
Request 1: [XOR'd Block 1 | Padding 15 bytes]  -> C2 = E(padding + flag[0])
Request 2: [XOR'd Block 1 | Padding 14 + guess] -> C2' = E(padding + guess)
If C2 == C2', then guess == flag[0]
```

### Method 2: Last 16 Bytes

After recovering the first 16 bytes, we use them as known plaintext:
1. XOR both IVs together to cancel their effects
2. Include known flag bytes in our crafted plaintext
3. Compare block 2 ciphertexts as before

## Solution Script

```python
import requests
import binascii

URL = "https://9cd2896dc2f9cedf.247ctf.com/"
possibilities = ['30','31','32','33','34','35','36','37','38','39',
                 '61','62','63','64','65','66']  # 0-9, a-f

def xor_operation(a, b):
    xored = []
    for i in range(len(a)):
        xored_value = ord(a[i % len(a)]) ^ ord(b[i % len(b)])
        xored.append(f"{xored_value:02x}")
    return ''.join(xored)

# Method 1: Recover first 16 bytes
session = requests.Session()
flag = ''
count = 31

for i in range(16):
    for guess in possibilities:
        text = chr(65 + (i % 16))  # Use different chars
        padding = binascii.hexlify((text * count).encode()).decode()

        # Get IV
        iv_resp = session.get(f"{URL}encrypt?plaintext={padding}")
        IV = bytes.fromhex(iv_resp.text[-32:]).decode('latin-1')

        # Request 1: XOR to nullify IV
        xored = xor_operation(IV, text * 16)
        r1 = session.get(f"{URL}encrypt?plaintext={xored}{padding[32:]}")

        # Request 2: With guess
        IV2 = bytes.fromhex(r1.text[-32:]).decode('latin-1')
        xored2 = xor_operation(IV2, text * 16)
        r2 = session.get(f"{URL}encrypt?plaintext={xored2}{padding[32:]}{flag}{guess}")

        if r1.text[32:64] == r2.text[32:64]:
            flag += guess
            count -= 1
            break

# Method 2 is similar, using known flag bytes
```

## Flag
```
247CTF{d4d651b2XXXXXXXXXXXXXXXX01fad941}
```

## Aprendizaje del reto

1. **BEAST Attack**: Exploits predictable IVs in CBC mode
2. **Chosen Plaintext Attack**: We control input and observe output
3. **XOR Cancellation**: XORing with known IV removes its effect
4. **Block Comparison**: Matching ciphertext blocks reveal correct guesses

## References
- [BEAST Attack Wikipedia](https://en.wikipedia.org/wiki/Transport_Layer_Security#BEAST_attack)
- [AES-CBC Mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC)
