# XYZOR

**Category:** CRYPTO
**Difficulty:** Easy
**Points:** 100
**Flag:** `HackOn{1_2_3_un_B1ts1T0_p4_Tr4s}`

## Description

> Acabo de desplegar la versión de prueba del algoritmo XYZOR. Según mis cálculos, es imposible de romper debido al vector de orden que se genera aleatoriamente en cada petición, el flujo de bits cambia siempre, así que nadie debería poder correlacionar los datos con la clave original...

## TL;DR

The XYZOR cipher XORs each plaintext bit with a key bit at a variable offset (0, 1, or 2) determined by a random order string. Since the order is disclosed alongside the ciphertext, sending known plaintexts to the encryption oracle lets us recover the key bits, which we then use to decrypt the flag.

## Analysis

The XYZOR algorithm works as follows:
- A secret **key** (bit string) is fixed on the server.
- For each encryption, a random **order** string of characters `x`, `y`, `z` is generated (same length as plaintext bits).
- For each bit position `i`:
  - If `order[i] = 'x'`: `ciphertext[i] = plaintext[i] XOR key[i]`
  - If `order[i] = 'y'`: `ciphertext[i] = plaintext[i] XOR key[i+1]`
  - If `order[i] = 'z'`: `ciphertext[i] = plaintext[i] XOR key[i+2]`

The `/flag` page provides the encrypted flag (256 bits) along with the order used.

The `/encrypt` endpoint accepts arbitrary plaintext and returns plaintext_bits, ciphertext_bits, and the random order.

**The vulnerability:** Since the order is always revealed, and XOR is self-inverse, sending a known plaintext lets us recover key bits:

```
key[i + offset] = plaintext[i] XOR ciphertext[i]
```

By sending a few requests with known plaintext, we recover all key bit positions needed to decrypt the flag.

## Solution

### Prerequisites

```bash
pip install requests --break-system-packages
```

### Steps

1. Fetch `/flag` to get the encrypted flag ciphertext (256 bits) and its order string.
2. Determine which key bit positions are needed (positions `i + offset` for each `i` in the flag order).
3. Send known plaintext (e.g., `"A" * 34`) to `/encrypt` repeatedly. Each response reveals key bits at positions determined by the random order.
4. After ~7 requests, all 176 unique key positions needed for the flag are recovered.
5. Decrypt: `flag_bit[i] = ciphertext[i] XOR key[i + offset(order[i])]`.

### Solve Script

```python
#!/usr/bin/env python3
import requests

URL = "https://hackon-crypto-xyzor-service.chals.io"
FLAG_CT = "1001000001111000101001100100010001010010100100010111011010010000111101110010001010101101111001111001000110110011011111100101111110110010001101111010011110110011110100011101001101010101010000000110111010100000100111100110000010010011011100010010011000010110"
FLAG_ORDER = "yxyyxyyzxxzxyyxzyxyzyyzzxzxzxzyxxyyzzzzzzyxzxyxzzzyxxzzxzxxyyyyzzzzxxzzyxxzzzzxxyxyxyyyyyyzzxxzzzzzyzzxyyxyxxyxyxzyyzyzxyxzyyyzyzzxxyxyxxzzzzzyyyzzxxxyxyxxzyyzyzzxyxyyxyzyyxzxxxyxxyzzxxyyyxxyxxzyyxyxxyyyyzxxyzzzyyxzzxzzzzxxzzyxyzyzzzxxzyzxzxyzzzxzxxyxzzxxz"
OFFSET = {'x': 0, 'y': 1, 'z': 2}

needed = {i + OFFSET[o] for i, o in enumerate(FLAG_ORDER)}
known_key = {}
plaintext = "A" * 34

while not needed.issubset(known_key.keys()):
    r = requests.post(f"{URL}/encrypt", data={"plaintext": plaintext}).json()
    for i in range(len(r["order"])):
        pos = i + OFFSET[r["order"][i]]
        known_key[pos] = int(r["plaintext_bits"][i]) ^ int(r["ciphertext_bits"][i])

flag_bits = ''.join(
    str(int(FLAG_CT[i]) ^ known_key[i + OFFSET[FLAG_ORDER[i]]])
    for i in range(len(FLAG_CT))
)
flag = bytes(int(flag_bits[i:i+8], 2) for i in range(0, len(flag_bits), 8)).decode()
print(flag)
```

## Flag

```
HackOn{1_2_3_un_B1ts1T0_p4_Tr4s}
```
