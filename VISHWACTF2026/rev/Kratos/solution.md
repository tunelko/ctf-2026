# Kratos — VishwaCTF 2026 (Reversing)

## TL;DR

Unity IL2CPP Android game. The flag is XOR-encrypted with single-byte key `0x6a` and stored in `global-metadata.dat`. No need to reverse the full game logic.

## Analysis

The APK is a Unity game compiled with IL2CPP. Key files:
- `libil2cpp.so` (65MB) - compiled C# game logic
- `global-metadata.dat` (8.6MB) - IL2CPP metadata with type/method names and string literals

Strings in the metadata reveal the game's `buttonBehaviour` class with methods:
- `OnSubmitClicked` → `ProcessSubmission` → `ComputeSHA256` → `DecryptFlag`
- Fields: `targetHash`, `flagCipher`, `xorKey`, `roasts`

Three SHA256 hashes are embedded as string literals. The intended flow requires entering a password whose SHA256 matches `targetHash`, then decrypting the flag via XOR.

## Shortcut

Instead of reversing the full decrypt flow, a single-byte XOR brute-force on the metadata finds the flag directly:

```python
with open('global-metadata.dat', 'rb') as f:
    meta = f.read()

for key in range(1, 256):
    target = bytes([b ^ key for b in b'VishwaCTF{'])
    idx = meta.find(target)
    if idx >= 0:
        full = meta[idx:idx+40]
        decoded = bytes([b ^ key for b in full])
        end = decoded.find(b'}') + 1
        print(f"Key 0x{key:02x}: {decoded[:end]}")
```

XOR key: `0x6a`

## Flag

```
VishwaCTF{y0u_g07_kr4t0s_G0D}
```
