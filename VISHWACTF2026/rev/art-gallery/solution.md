# Art Gallery — VishwaCTF 2026 (Reversing)

## TL;DR

Android APK with native library (`libartvault.so`). Invert the murmur hash to find the correct `runtimeSignal`, then reimplement the 4-step decryption: interleave 3 data arrays → apply permutation → XOR with LCG PRNG keystream → sbox substitution → bit rotation.

## Analysis

The APK has three activities: `MainActivity` → `GalleryActivity` → `CanvasActivity`. The flag decryption happens in `CanvasActivity` which loads `libartvault.so` and calls two JNI functions:

1. `verifyGateNative(signal)` — checks `murmur_hash(signal ^ 0x6c8e9cf5) == 0xd15ea5ed`
2. `decryptFlagNative(signal)` — decrypts the flag using the signal

The `signal` is computed from the APK's package name hash and signing certificate, but we bypass this by inverting the murmur hash.

### Signal Recovery

The verify function uses a murmur3 finalizer hash. Since it's bijective, we invert it:

```
target = 0xd15ea5ed
input = invert_murmur(target)  → 0x00e78b93
signal = input ^ 0x6c8e9cf5   → 0x6c691766
```

### Decryption Algorithm (from `libartvault.so`)

**Step 1 — Interleave:** Three 11-byte arrays at offsets `0x10061`, `0x1006c`, `0x10077` are interleaved based on `i % 3`.

**Step 2 — Permutation:** A 33-byte permutation table at `0x10040` reorders the data: `buf[i] = interleaved[perm[i]]`.

**Step 3 — PRNG XOR:** LCG with seed `0x7f4a7c15`, multiplier `0x19660d`, increment `0x3c6ef35f`. Key byte extracted from different positions based on `i & 3`, then XORed with `i * 31 + 17`.

**Step 4 — Sbox + Rotation:** 4-bit sbox substitution on each nibble, then rotate right by `(i % 5) + 1` bits.

## Flag

```
VishwaCTF{secret_gallery_exposed}
```

## Key Lessons

- Native Android libs with anti-debug checks can be analyzed purely statically
- Murmur3 finalizer hash is bijective — easily invertible by reversing each step
- Complex multi-stage encryption (interleave → permute → XOR → sbox → rotate) is still breakable when all parameters are embedded in the binary
