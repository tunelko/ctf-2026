# Cheater Cheater — DawgCTF 2026 (REV)

## TL;DR
Java Pac-Man game with AES-encrypted flag. Decompile JAR, trace win condition logic, compute AES key/IV from score value, decrypt.

## Analysis
- `PacManForCTF.jar` — Swing Pac-Man game ("Hac-Man")
- Highscore to beat: 6,942,069 — unreachable by normal play (score increments by 10, game kills you at 64,000)
- Win condition in `actionPerformed`: `score >= 6942069` → `winner = true`

## Flag Decryption Flow
1. On win, `SimplePacMan.setName("6942069")` is called
2. `getComponents()[0].revalidate()` triggers `JTextBasket.revalidate()`
3. `revalidate()` computes:
   - `val = ((6942069 * 10) + 1) ^ 4 = 69420691^4 = 23225000336468054454242927385361`
   - AES Key = `hexStringToByteArray(val)` → `\x23\x22\x50\x00\x33\x64\x68\x05\x44\x54\x24\x29\x27\x38\x53\x61`
   - IV = `hexStringToByteArray(reverse(val))` → `\x16\x35\x83\x72\x92\x42\x45\x44\x50\x86\x46\x33\x00\x05\x22\x32`
4. Decrypts base64 ciphertext with AES/CBC/PKCS5Padding
5. Sets component name to decrypted flag, displayed on win screen

## Key Insight
The `flag` field in `SimplePacMan` is a red herring ("THIS IS NOT HOW YOU ARE SUPPOSED TO DO THE CHALLENGE..."). The real flag is AES-encrypted in `JTextBasket.revalidate()` using the base64 string stored in `pacVelocityZ`.

## Flag
```
DawgCTF{ch3at3R_ch34t3r_pumk1n_34t3r!}
```
