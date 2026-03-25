# DodecaCrypt

| Campo       | Valor              |
|-------------|--------------------|
| Plataforma  | BSidesSF 2026      |
| Categoría   | Crypto             |
| Dificultad  | Medium-Hard        |
| Puntos      | 516                |
| Autor       | symmetric          |

## Descripción
> Symmetric is rolling the dice this year that you want more crypto challenges! What do his dice say? (Note, flag format is CTF{THIS_IS_AN_EXAMPLE}, you will need to add the CTF{} manually.)

## TL;DR
A web app encodes messages as colored dodecahedra. Reverse-engineer the encoding (base-120 with key-determined color permutations), identify the encryption key (`XYLOGRAPHICS`) from the color palette in the flag image, extract face colors, and decode.

## Análisis inicial

The challenge provides:
- A web app at `https://dodecacrypt-949351df.challenges.bsidessf.net/`
- A PNG image (`flag.png`) containing 26 colored dodecahedra in a grid

The web app has:
- A message input, a secret key input, and an "Encrypt" button
- A canvas rendering dodecahedra with colored faces
- An API endpoint `POST /api/encrypt` returning JSON with dodecahedra face color arrays
- Client-side JS (`dodecahedron.js`) handling 3D rendering

```bash
curl -s -X POST https://dodecacrypt-949351df.challenges.bsidessf.net/api/encrypt \
  -H 'Content-Type: application/json' \
  -d '{"key":"A","message":"A"}' | python3 -m json.tool
```

Response includes `sanitized_key`, `sanitized_message`, `count`, and `dodecahedra` (array of 12-color arrays per dodecahedron).

## Proceso de resolución

### Paso 1: Understand the encoding scheme

**Charset**: Messages are uppercased, spaces → underscores, digits removed. Valid chars: `_` and `A-Z` (27 values).

**Key sanitization**: Key is uppercased, padded with `ABCDEFGHIJK...` to 12 characters.

**Capacity per dodecahedron**: By testing messages of increasing length and tracking the dodecahedron count, I found the overflow boundary:

```
"DK" → 1 dodecahedron
"DL" → 2 dodecahedra
```

With charset ordering `_=0, A=1, ..., Z=26`: `"DK" = 4*27+11 = 119`, `"DL" = 120`. So each dodecahedron encodes values **0–119** (base 120).

The dodecahedron count follows: `count = floor((2*(n-1))/3) + 1` where n = message length. The encoding is a **big-endian base-120 decomposition** of the message value (interpreted as a base-27 number).

Verified that dodecahedra encode values **independently** (same value → same colors regardless of position), but changing one message character affects ALL dodecahedra (global base conversion).

### Paso 2: Determine the letter-to-color mapping

Each of the 26 letters maps to a **fixed color** regardless of key or position:

```
A → #e6194b (red)       N → #fffac8 (cream)
B → #3cb44b (green)     O → #800000 (maroon)
C → #ffe119 (yellow)    P → #aaffc3 (mint)
D → #4363d8 (blue)      Q → #808000 (olive)
E → #f58231 (orange)    R → #ffd8b1 (peach)
F → #911eb4 (purple)    S → #000075 (navy)
G → #46f0f0 (cyan)      T → #808080 (gray)
H → #f032e6 (magenta)   U → #ff7f00 (amber)
I → #bcf60c (lime)      V → #00a6ff (sky blue)
J → #fabebe (pink)      W → #d81b60 (rose)
K → #008080 (teal)      X → #4caf50 (forest)
L → #e6beff (lavender)  Y → #aa00ff (violet)
M → #9a6324 (brown)     Z → #00c853 (emerald)
```

Determined by encrypting with keys containing each letter at specific positions and observing which face color changed.

### Paso 3: Determine the key-position-to-face mapping

By modifying one key character at a time and observing which face changed:

```
Key position:  0  1  2  3  4  5  6  7  8  9 10 11
Maps to face:  9  8  2  6  1 11 10  7  0  4  5  3
```

Inverse (face → key position): `[8, 4, 2, 11, 9, 10, 3, 7, 1, 0, 6, 5]`

### Paso 4: Determine value-to-permutation table

For value 0, face colors equal the key's base colors. For value V, a **key-independent permutation** is applied. Built all 120 permutations using a 12-unique-char key (`ABCDEFGHIJKL`):

```python
# For each value V, face[j] = val0_colors[perm_V[j]]
# Verified: same permutation regardless of key
```

### Paso 5: Extract face colors from the flag image

The dodecahedron is rendered with rotation (45°, 0°, 0°). Computed the 3D geometry (20 vertices, 12 pentagonal faces) and determined 6 front-facing faces at these 2D positions:

| Face | Position     | Relative coords (×scale) |
|------|-------------|--------------------------|
| 6    | top         | (0, +1.34)               |
| 11   | upper-right | (+1.17, +0.51)           |
| 5    | upper-left  | (−1.17, +0.51)           |
| 7    | center      | (0, +0.32)               |
| 10   | lower-right | (+0.72, −0.83)           |
| 3    | lower-left  | (−0.72, −0.83)           |

Sampled each face position with 5×5 pixel averaging, matching against all 26 letter colors. Image has 26 dodecahedra (not 32 — the lower-right cells are empty background).

### Paso 6: Identify the encryption key

The extracted colors across all 26 dodecahedra used exactly **12 unique letters**: `{A, C, G, H, I, L, O, P, R, S, X, Y}`.

Since the key is 12 characters and must contain all 12 unique colors, the key is a permutation of these letters. The word **`XYLOGRAPHICS`** (relating to wood engraving) contains exactly these 12 unique letters — confirmed as the key:

```bash
curl -s -X POST .../api/encrypt -d '{"key":"XYLOGRAPHICS","message":"A"}'
# sanitized_key: "XYLOGRAPHICS" — 12 unique chars matching the target set ✓
```

### Paso 7: Decode the flag

```python
# For key XYLOGRAPHICS, compute val0_colors using face_to_key_pos mapping
# For each dodecahedron: find the value V whose permutation produces matching visible face colors
# All 26 dodecahedra matched uniquely → 26 base-120 values
# Convert from base-120 to a single number, then to base-27 characters

vals = [matched_values]  # 26 values, one per dodecahedron
num = 0
for v in vals:
    num = num * 120 + v
charset = "_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
chars = []
while num > 0:
    chars.append(charset[num % 27])
    num //= 27
flag = ''.join(reversed(chars))
# → HI_IM_SYMMETRIC_AND_THIS_IS_YOUR_FLAG
```

## Flag
```
CTF{HI_IM_SYMMETRIC_AND_THIS_IS_YOUR_FLAG}
```

## Key Lessons
- **Base conversion ciphers**: The encoding converts base-27 (charset) to base-120 (dodecahedron capacity). Finding the capacity via boundary testing was key.
- **Fixed mappings are exploitable**: The letter→color and value→permutation mappings are both key-independent, meaning the key ONLY determines the base color assignment. This separates the problem into independent sub-problems.
- **Color palette reveals the key**: The set of 12 unique colors in the flag image directly identifies the 12 key characters. The word XYLOGRAPHICS is the only common English word with exactly these letters.
- **Pixel extraction needs care**: Initial extraction failed because face centroid positions can land on edges or background. Using the full 26-letter color palette (not just 11 assumed colors) and multi-pixel averaging fixed the extraction.

## Referencias
- Dodecahedron geometry: 20 vertices, 30 edges, 12 pentagonal faces
- The 120 in the base comes from 12 × 10 (related to the dodecahedron's face permutation structure)
- XYLOGRAPHICS: art/technique of wood engraving — a 12-letter word with all unique characters
