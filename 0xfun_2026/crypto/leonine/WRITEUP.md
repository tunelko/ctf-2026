# Leonine Misbegotten — Crypto (50pts)

> "At the end of Castle Morne awaits a fearsome lion with a goofy tail. His attacks come fast, feel random, yet follow a careful rhythm."

## Summary

Multi-layer decoding challenge. The flag is encoded 16 times using random encoding schemes (base16, base32, base64, base85). Each layer includes a SHA1 checksum that allows verifying which scheme was used. The solution consists of decoding layer by layer, trying each scheme until the checksum matches.

**Flag:** `0xfun{p33l1ng_l4y3rs_l1k3_an_0n10n}`

## Challenge Analysis

### Files provided

```
chall_Leonine.py    # Challenge generation code
output              # Encoded flag (76,996 bytes)
```

### The encoding scheme

```python
from base64 import b16encode, b32encode, b64encode, b85encode
from hashlib import sha1
from random import choice

SCHEMES = [b16encode, b32encode, b64encode, b85encode]

ROUNDS = 16
current = flag.encode()
for _ in range(ROUNDS):
    checksum = sha1(current).digest()  # 20 bytes
    current = choice(SCHEMES)(current)  # Encode with random scheme
    current += checksum                 # Append checksum at the end
```

**Process:**
1. Start with the flag as bytes
2. For each of the 16 rounds:
   - Compute the SHA1 of the current content (20 bytes)
   - Encode with a random scheme (b16, b32, b64 or b85)
   - Append the checksum at the end
3. The final output is a ~77KB file

### Key observations

1. **The checksum is the key**: The last 20 bytes of each layer contain the SHA1 of the content *before* encoding.

2. **Only one scheme will work**: When trying to decode:
   - If we use the correct scheme -> successful decoding + checksum matches
   - If we use an incorrect scheme -> decoding error or checksum mismatch

3. **Decoding order**: We must decode in reverse order (round 16 -> round 1).

## Solution

### Strategy

For each round (from 16 to 1):
1. Separate the last 20 bytes (SHA1 checksum)
2. Try to decode the rest with each of the 4 schemes
3. For each successful attempt, verify if SHA1(decoded) == checksum
4. The scheme with matching checksum is the correct one
5. Continue with the decoded content to the next round

### Implementation

```python
from base64 import b16decode, b32decode, b64decode, b85decode
from hashlib import sha1

DECODERS = {
    'base16': b16decode,
    'base32': b32decode,
    'base64': b64decode,
    'base85': b85decode
}

ROUNDS = 16

def decode_round(data):
    """
    Try to decode a round by testing each scheme.
    Returns (decoded_data, scheme_used) if successful
    """
    # The last 20 bytes are the SHA1 checksum
    checksum = data[-20:]
    encoded = data[:-20]

    # Try each decoding scheme
    for scheme_name, decoder in DECODERS.items():
        try:
            decoded = decoder(encoded)

            # Verify checksum
            if sha1(decoded).digest() == checksum:
                return decoded, scheme_name

        except Exception:
            continue  # Try next scheme

    return None

def solve():
    with open("output", "rb") as f:
        data = f.read()

    current = data

    # Decode each round
    for round_num in range(ROUNDS, 0, -1):
        result = decode_round(current)
        if result is None:
            print(f"ERROR at round {round_num}")
            return None
        current, scheme = result
        print(f"Round {round_num}: {scheme}")

    # The final result is the flag
    flag = current.decode('utf-8')
    print(f"\nFLAG: {flag}")
    return flag
```

### Execution

```bash
$ python3 leonine_solve.py
[*] Initial output size: 76996 bytes
[*] Decoding 16 rounds...

=== Round 16 ===
[+] Round decoded with base32
    Size before: 76996 bytes -> Size after: 48110 bytes

=== Round 15 ===
[+] Round decoded with base16
    Size before: 48110 bytes -> Size after: 24045 bytes

=== Round 14 ===
[+] Round decoded with base85
    Size before: 24045 bytes -> Size after: 19220 bytes

... (more rounds) ...

=== Round 1 ===
[+] Round decoded with base16
    Size before: 90 bytes -> Size after: 35 bytes

============================================================
[+] FLAG FOUND!
[+] 0xfun{p33l1ng_l4y3rs_l1k3_an_0n10n}
============================================================
```

### Schemes used (in order of application)

```
Round  1: base16
Round  2: base16
Round  3: base64
Round  4: base85
Round  5: base64
Round  6: base85
Round  7: base16
Round  8: base16
Round  9: base32
Round 10: base32
Round 11: base64
Round 12: base85
Round 13: base32
Round 14: base85
Round 15: base16
Round 16: base32
```

## Complexity

- **Time:** O(ROUNDS x SCHEMES) = O(16 x 4) = 64 attempts maximum
- **In practice:** ~1 second in pure Python
- **Space:** O(output_size) ~ 77KB

Each round only requires trying 4 schemes at most. In practice, the correct scheme is usually found in 1-2 attempts due to decoding errors with incorrect schemes.

## Encoding scheme analysis

### Expansion rates

Each scheme has a different expansion rate:

| Scheme | Expansion | Example: 100 bytes -> |
|--------|-----------|----------------------|
| base16 | 2.0x      | 200 bytes            |
| base32 | 1.6x      | 160 bytes            |
| base64 | 1.33x     | 133 bytes            |
| base85 | 1.25x     | 125 bytes            |

In our case:
- **Initial input:** 35 bytes (flag)
- **Final output:** 76,996 bytes
- **Total expansion:** ~2,200x
- **Average expansion per round:** ~1.73x (consistent with a mix of schemes)

## Flag interpretation

`0xfun{p33l1ng_l4y3rs_l1k3_an_0n10n}`

- **"peeling layers like an onion"** -> Direct reference to the layer-by-layer decoding process
- Wordplay with "onion routing" (Tor network) which also uses encryption layers
- Each layer hides the next one, similar to the layers of an onion

## Lessons Learned

1. **Checksums are invaluable**: Without the SHA1 checksum, this challenge would be much harder. We would need to:
   - Try all possible combinations of 16 schemes: 4^16 = 4.3 billion
   - Use heuristics to detect correct decoding (valid characters, etc.)

2. **Encoding != Encryption**:
   - Encoding schemes (base64, etc.) are NOT cryptographic
   - They are deterministically reversible
   - They only obfuscate, they don't protect

3. **Randomness adds complexity**: Using `random.choice()` means each instance of the challenge has a different sequence of schemes.

4. **Try-except is your friend**: When trying multiple decoders, exception handling is essential since incorrect schemes usually generate errors.

5. **The challenge name was a hint**:
   - "Leonine Misbegotten" -> Boss from Elden Ring at **Castle Morne**
   - "goofy tail" -> The flag has a "tail" (checksum) that looks strange but is useful
   - "attacks come fast, feel random, yet follow a careful rhythm" -> Random schemes but with a verifiable pattern

## References

- [Base64 encoding - Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [Python base64 module](https://docs.python.org/3/library/base64.html)
- [SHA-1 hash function](https://en.wikipedia.org/wiki/SHA-1)
- [Elden Ring Wiki - Leonine Misbegotten](https://eldenring.wiki.fextralife.com/Leonine+Misbegotten)

## Note

This is a "beginner" level challenge (50pts) that serves as an introduction to:
- Multi-layer decoding
- Using checksums for verification
- Handling different encoding schemes
- Scripting for automation

The presence of the SHA1 checksum significantly simplifies the challenge, turning it into a search-with-verification problem instead of a pure combinatorial problem.
