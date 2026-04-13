// Reimplement the decrypt logic from libartvault.so
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Sbox at 0x12157
static const uint8_t sbox[16] = {0x06,0x04,0x0c,0x05,0x00,0x07,0x02,0x0e,0x01,0x0f,0x03,0x0d,0x08,0x0a,0x09,0x0b};

static uint8_t apply_sbox(uint8_t b) {
    return (sbox[(b >> 4) & 0xF] << 4) | sbox[b & 0xF];
}

// Murmur finalizer hash
static uint32_t murmur_hash(uint32_t val) {
    val = (val >> 16) ^ val;
    val *= 0x7feb352d;
    val = (val >> 15) ^ val;
    val *= 0x846ca68b;
    val = (val >> 16) ^ val;
    return val;
}

int main() {
    // Three data arrays from .rodata
    uint8_t arr0[] = {0xc1,0xe8,0x1f,0xf4,0xac,0x02,0xc6,0x08,0x0f,0x61,0x35};
    uint8_t arr1[] = {0x99,0x9f,0x79,0xb5,0x53,0xf3,0xde,0xdc,0x23,0x7c,0xf9};
    uint8_t arr2[] = {0x9a,0x10,0x5e,0xee,0x23,0x5d,0x97,0x9e,0x4b,0x1f,0xb3};

    // Permutation table at 0x10040
    uint8_t perm[] = {32,28,17,16,8,7,19,1,5,0,4,15,18,21,14,29,2,22,13,3,30,6,27,9,11,25,20,12,31,26,24,10,23};

    int n = 33;

    // Step 1: Interleave arrays based on i%3
    uint8_t interleaved[33];
    int c0=0, c1=0, c2=0;
    for (int i = 0; i < n; i++) {
        switch (i % 3) {
            case 0: interleaved[i] = arr0[c0++]; break;
            case 1: interleaved[i] = arr1[c1++]; break;
            case 2: interleaved[i] = arr2[c2++]; break;
        }
    }

    // Step 2: Apply permutation
    uint8_t unperm[33];
    for (int i = 0; i < n; i++) {
        unperm[i] = interleaved[perm[i]];
    }

    // Step 3: PRNG XOR decrypt + sbox + modular transform
    uint32_t seed = 0x7f4a7c15;
    uint8_t result[33];

    for (int i = 0; i < n; i++) {
        seed = seed * 0x19660d + 0x3c6ef35f;
        int shift = (i & 3) * 8;
        uint8_t key_byte = (seed >> shift) & 0xFF;
        uint8_t extra = key_byte ^ ((uint8_t)(i * 31 + 17));
        uint8_t dec = unperm[i] ^ extra;
        dec = apply_sbox(dec);

        // i%5 transform from disasm around 0x1f2fc-0x1f370
        // The division by 5 (0xcccccccccccccccd magic) and remainder check
        // followed by XOR with (i/5) or similar
        if (i % 5 == 0) {
            dec ^= (uint8_t)(i / 5);
        }

        result[i] = dec;
    }

    printf("With i%%5 XOR: ");
    for (int i = 0; i < n; i++) printf("%c", result[i] >= 32 && result[i] < 127 ? result[i] : '?');
    printf("\n");

    // Try without i%5 transform
    seed = 0x7f4a7c15;
    for (int i = 0; i < n; i++) {
        seed = seed * 0x19660d + 0x3c6ef35f;
        int shift = (i & 3) * 8;
        uint8_t key_byte = (seed >> shift) & 0xFF;
        uint8_t extra = key_byte ^ ((uint8_t)(i * 31 + 17));
        result[i] = unperm[i] ^ extra;
        result[i] = apply_sbox(result[i]);
    }
    printf("Without i%%5: ");
    for (int i = 0; i < n; i++) printf("%c", result[i] >= 32 && result[i] < 127 ? result[i] : '?');
    printf("\n");

    // Try: sbox is applied during encryption, so we need INVERSE sbox
    uint8_t inv_sbox[16];
    for (int i = 0; i < 16; i++) inv_sbox[sbox[i]] = i;

    seed = 0x7f4a7c15;
    for (int i = 0; i < n; i++) {
        seed = seed * 0x19660d + 0x3c6ef35f;
        int shift = (i & 3) * 8;
        uint8_t key_byte = (seed >> shift) & 0xFF;
        uint8_t extra = key_byte ^ ((uint8_t)(i * 31 + 17));
        // Maybe: inv_sbox first, then XOR
        uint8_t s = (inv_sbox[(unperm[i] >> 4) & 0xF] << 4) | inv_sbox[unperm[i] & 0xF];
        result[i] = s ^ extra;
    }
    printf("inv_sbox->XOR (unperm): ");
    for (int i = 0; i < n; i++) printf("%c", result[i] >= 32 && result[i] < 127 ? result[i] : '?');
    printf("\n");

    // Try all combos with interleaved (no unperm)
    seed = 0x7f4a7c15;
    for (int i = 0; i < n; i++) {
        seed = seed * 0x19660d + 0x3c6ef35f;
        int shift = (i & 3) * 8;
        uint8_t key_byte = (seed >> shift) & 0xFF;
        uint8_t extra = key_byte ^ ((uint8_t)(i * 31 + 17));
        uint8_t s = (inv_sbox[(interleaved[i] >> 4) & 0xF] << 4) | inv_sbox[interleaved[i] & 0xF];
        result[i] = s ^ extra;
    }
    printf("inv_sbox->XOR (no unperm): ");
    for (int i = 0; i < n; i++) printf("%c", result[i] >= 32 && result[i] < 127 ? result[i] : '?');
    printf("\n");

    return 0;
}
