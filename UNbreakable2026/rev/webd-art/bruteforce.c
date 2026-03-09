#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Stored array (40 elements). Globals resolved: g530=70, g531=4, g532=198, g533=150
static const int stored[40] = {
    218, 78, 141, 70/*g530*/, 79, 33, 46, 234, 174, 75,
    4/*g531*/, 130, 143, 169, 189, 93, 127, 4/*g531*/, 198/*g532*/, 150/*g533*/,
    239, 47, 94, 136, 89, 231, 203, 209, 88, 150/*g533*/,
    122, 147, 60, 167, 251, 224, 198/*g532*/, 100, 50, 163
};

// Positions with known stored values
static const int known_pos[] = {0,1,2,4,5,6,7,8,9,11,12,13,14,15,16,20,21,22,23,24,25,26,27,28,30,31,32,33,34,35,37,38,39};
static const int n_known = 33;

// Unknown positions
static const int unknown_pos[] = {3, 10, 17, 18, 19, 29, 36};
static const int n_unknown = 7;

static inline uint8_t prng_byte(uint32_t state) {
    uint32_t m = state ^ (state >> 16);
    m *= 0x85EBCA6BU;
    m ^= (m >> 13);
    m *= 0xC2B2AE35U;
    m ^= (m >> 16);
    return (uint8_t)(m & 0xFF);
}

int main() {
    // For the correct seed, prng outputs XORed with stored array give the flag
    // flag[0]='C'=0x43, flag[1]='T'=0x54, flag[2]='F'=0x46, flag[39]='}'=0x7D
    // prng[0] = 0x43 ^ 218 = 0x99
    // prng[1] = 0x54 ^ 78  = 0x1A
    // prng[2] = 0x46 ^ 141 = 0xCB

    // Weyl sequence: state[i] = (seed + (i+1)*0x9E3779B9) & 0xFFFFFFFF
    // prng_byte[i] = murmurhash3_fmix32(state[i]) & 0xFF

    uint8_t target0 = 0x43 ^ 218;  // 0x99
    uint8_t target1 = 0x54 ^ 78;   // 0x1A
    uint8_t target2 = 0x46 ^ 141;  // 0xCB
    uint8_t target39 = 0x7D ^ 163; // 0xDE

    printf("Targets: prng[0]=0x%02x prng[1]=0x%02x prng[2]=0x%02x prng[39]=0x%02x\n",
           target0, target1, target2, target39);

    uint64_t tested = 0;
    for (uint64_t seed64 = 0; seed64 < 0x100000000ULL; seed64++) {
        uint32_t seed = (uint32_t)seed64;

        // Check byte 0
        uint32_t s = seed + 0x9E3779B9U;
        if (prng_byte(s) != target0) continue;

        // Check byte 1
        s += 0x9E3779B9U;
        if (prng_byte(s) != target1) continue;

        // Check byte 2
        s += 0x9E3779B9U;
        if (prng_byte(s) != target2) continue;

        // Check byte 39 (state = seed + 40*0x9E3779B9)
        uint32_t s39 = seed + 40U * 0x9E3779B9U;
        if (prng_byte(s39) != target39) continue;

        // Candidate found! Generate full flag
        printf("\n[+] Candidate seed: 0x%08x\n", seed);

        char flag[41];
        int valid = 1;
        uint32_t state = seed;
        for (int i = 0; i < 40; i++) {
            state += 0x9E3779B9U;
            uint8_t pb = prng_byte(state);

            // For known positions, compute flag char
            if (stored[i] != 0 || i == 3 || i == 10 || i == 17 || i == 18 || i == 19 || i == 29 || i == 36) {
                if (i == 3 || i == 10 || i == 17 || i == 18 || i == 19 || i == 29 || i == 36) {
                    // Unknown stored value - flag char is unknown
                    // But flag char must be printable ASCII (0x20-0x7E)
                    // We'll fill in '?' for now
                    flag[i] = '?';
                } else {
                    flag[i] = pb ^ stored[i];
                    // Check printable ASCII for positions 4-38 (inside CTF{...})
                    if (i >= 4 && i <= 38 && (flag[i] < 0x20 || flag[i] > 0x7E)) {
                        valid = 0;
                    }
                }
            }
        }
        flag[40] = '\0';

        if (!valid) {
            printf("    Invalid (non-printable chars in known positions)\n");
            continue;
        }

        printf("    Flag (partial): %s\n", flag);

        // Now try all possible values for unknown globals
        // global[530] at pos 3: flag[3] = prng[3] ^ g530 = '{' = 0x7B
        // So g530 = prng[3] ^ 0x7B
        state = seed + 4U * 0x9E3779B9U;
        uint8_t pb3 = prng_byte(state);
        uint8_t g530 = pb3 ^ 0x7B;
        flag[3] = '{';

        // For other unknown positions, the flag chars should be printable
        // Let me compute what the globals would need to be

        // Compute PRNG bytes at unknown positions
        uint8_t prng_bytes[40];
        state = seed;
        for (int i = 0; i < 40; i++) {
            state += 0x9E3779B9U;
            prng_bytes[i] = prng_byte(state);
        }

        // g530: pos 3, flag[3]='{', so g530 = prng[3] ^ '{'
        g530 = prng_bytes[3] ^ 0x7B;
        // g531: pos 10 and 17
        // g532: pos 18 and 36
        // g533: pos 19 and 29

        // For each unknown global, we need: flag[pos] = prng[pos] ^ global_val
        // And flag[pos] must be printable ASCII
        // Also, same global must give consistent printable values at both positions

        // Brute force globals 531, 532, 533 (0-255)
        for (int g531 = 0; g531 < 256; g531++) {
            char c10 = prng_bytes[10] ^ g531;
            char c17 = prng_bytes[17] ^ g531;
            if (c10 < 0x20 || c10 > 0x7E || c17 < 0x20 || c17 > 0x7E) continue;

            for (int g532 = 0; g532 < 256; g532++) {
                char c18 = prng_bytes[18] ^ g532;
                char c36 = prng_bytes[36] ^ g532;
                if (c18 < 0x20 || c18 > 0x7E || c36 < 0x20 || c36 > 0x7E) continue;

                for (int g533 = 0; g533 < 256; g533++) {
                    char c19 = prng_bytes[19] ^ g533;
                    char c29 = prng_bytes[29] ^ g533;
                    if (c19 < 0x20 || c19 > 0x7E || c29 < 0x20 || c29 > 0x7E) continue;

                    // Build complete flag
                    char full[41];
                    memcpy(full, flag, 40);
                    full[40] = '\0';
                    full[3] = '{';
                    full[10] = c10;
                    full[17] = c17;
                    full[18] = c18;
                    full[19] = c19;
                    full[29] = c29;
                    full[36] = c36;

                    // Verify FNV-1a hash -> seed derivation -> matches assumed seed
                    uint32_t fnv = 0x811C9DC5U;
                    for (int i = 0; i < 40; i++) {
                        fnv ^= (uint8_t)full[i];
                        fnv *= 0x01000193U;
                    }

                    // Seed derivation: splitmix32 finalizer on fnv hash
                    // From disassembly: hash_mix = fnv (since it's already 32-bit)
                    // Actually the hash check uses two 64-bit components...
                    // For now assume hash_mix = fnv
                    uint32_t v = fnv;
                    v ^= (v >> 16);
                    v *= 0x7FEB352DU;
                    v ^= (v >> 15);
                    v *= 0x846CA68BU;
                    v ^= (v >> 16);
                    uint32_t derived_seed = (v != 0) ? v : 0xC0FFEE42U;

                    if (derived_seed == seed) {
                        printf("\n[+] FLAG FOUND!\n");
                        printf("    Seed: 0x%08x\n", seed);
                        printf("    FNV hash: 0x%08x\n", fnv);
                        printf("    g530=%d g531=%d g532=%d g533=%d\n", g530, g531, g532, g533);
                        printf("    Flag: %s\n", full);
                        return 0;
                    }
                }
            }
        }
        printf("    No valid global combination found for this seed\n");
    }

    printf("\nBrute force complete. No flag found.\n");
    return 1;
}
