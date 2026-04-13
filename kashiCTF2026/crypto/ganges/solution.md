# Ganges Oracle

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | KashiCTF 2026                  |
| Categoría   | crypto                         |
| Dificultad  | Hard                           |

## Descripcion
> In Kashi, even the dead whisper secrets. [...] Five ghats. Five messages. One carries the truth.

## TL;DR
AES-CTR nonce reuse (many-time pad) with per-message single-byte XOR obfuscation. Crib drag across 5 messages to recover keystream and flag.

## Vulnerabilidad
**CWE-323: Reusing a Nonce/IV** — AES-CTR with same key+nonce for 5 messages. Additionally, each ciphertext XORed with a different constant byte as post-processing.

## Proceso de resolucion

### Paso 1: Identificar las mascaras de obfuscacion

Cada ciphertext fue XORed con un byte constante despues del cifrado:
- c0: `0x14`
- c1: `0x20`  
- c2: `0x9f`
- c3: `0x05`
- c4: `0x00`

Encontradas por brute-force: para cada mascara, verificar si los primeros 5 bytes del plaintext son texto legible.

### Paso 2: Crib dragging

Tras remover las mascaras, XOR de pares da el XOR de plaintexts. Cribs encontrados:
- p0 = `"The quick brown fox..."` (pangrama)
- p1 = `"Hello! Today the weather..."` 
- p2 = `"Cryptography is fun but nonce reuse..."`
- p3 = `"Never gonna give you up..."`  (rickroll)
- p4 = `"kashiCTF{...}"` (flag)

### Paso 3: Recuperar keystream completo

Usando plaintexts conocidos (especialmente p4 = flag y p0 = pangrama), se recupera el keystream byte a byte, verificando consistencia en los 5 mensajes.

## Flag
```
kashiCTF{cr1b_dr4g_g03s_brrr_n0nc3_reuse_1s_4lw4ys_fatal}
```

## Key Lessons
- Per-message single-byte XOR after CTR encryption breaks standard crib-drag tools — must identify and remove masks first
- Masks discoverable via first-5-bytes brute force: only 256 candidates per message
- Cross-referencing 5+ messages makes crib dragging much more reliable
- "Padding is a lie" was literal — PAD appeared as text in the plaintext, not as actual PKCS padding
