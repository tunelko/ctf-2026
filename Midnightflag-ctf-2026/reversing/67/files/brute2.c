#include <stdio.h>
#include <stdint.h>
#include <string.h>

static uint32_t hash_group(uint8_t b0, uint8_t b1, uint8_t b2, uint32_t ebx_in) {
    uint32_t ecx = ((uint32_t)b0 << 16) | ((uint32_t)b1 << 8) | b2;
    ecx ^= ebx_in;
    uint32_t ebp = ecx;
    for (int i = 0; i < 1000; i++) {
        ecx ^= (ecx << 13);
        ecx ^= (ecx >> 17);
        ecx ^= (ecx << 5);
        ecx *= 0x2545f491;
    }
    return ecx ^ ebp;
}

int main() {
    // 4 compare values, 5 loads (5th has no compare, just halt)
    uint32_t expected[4] = {0x29a5b7cc, 0xd0e8a4e7, 0x5f5ec278, 0x0e9bff41};
    uint32_t ebx = 0xdeadbeef;
    uint8_t result[16] = {0};

    for (int group = 0; group < 4; group++) {
        int found = 0;
        // Full byte range
        for (int b0 = 0; b0 < 256 && !found; b0++) {
            for (int b1 = 0; b1 < 256 && !found; b1++) {
                for (int b2 = 0; b2 < 256 && !found; b2++) {
                    uint32_t res = hash_group(b0, b1, b2, ebx);
                    if (res == expected[group]) {
                        result[group*3] = b0;
                        result[group*3+1] = b1;
                        result[group*3+2] = b2;
                        ebx = res;
                        found = 1;
                        fprintf(stderr, "Group %d: 0x%02x 0x%02x 0x%02x '%c%c%c' -> 0x%08x\n",
                                group, b0, b1, b2,
                                (b0>=0x20&&b0<0x7f)?b0:'.',
                                (b1>=0x20&&b1<0x7f)?b1:'.',
                                (b2>=0x20&&b2<0x7f)?b2:'.',
                                res);
                    }
                }
            }
        }
        if (!found) {
            fprintf(stderr, "Group %d: NOT FOUND\n", group);
            return 1;
        }
    }

    // Group 4 (5th load): no compare, any 3 bytes work
    // But the flag is 15 bytes. Let me just print what we have.
    fprintf(stderr, "ebx after group 3: 0x%08x\n", ebx);
    printf("Input (12 bytes): ");
    for (int i = 0; i < 12; i++) printf("%02x", result[i]);
    printf("\nAs text: %.12s\n", result);

    // Check if there are collisions - maybe there's another solution for group 0
    // that starts with a printable char
    fprintf(stderr, "\nLooking for ALL solutions for group 0...\n");
    ebx = 0xdeadbeef;
    for (int b0 = 0; b0 < 256; b0++) {
        for (int b1 = 0; b1 < 256; b1++) {
            for (int b2 = 0; b2 < 256; b2++) {
                uint32_t res = hash_group(b0, b1, b2, ebx);
                if (res == expected[0]) {
                    fprintf(stderr, "  G0: 0x%02x 0x%02x 0x%02x '%c%c%c'\n",
                            b0, b1, b2,
                            (b0>=0x20&&b0<0x7f)?b0:'.',
                            (b1>=0x20&&b1<0x7f)?b1:'.',
                            (b2>=0x20&&b2<0x7f)?b2:'.');
                }
            }
        }
    }

    return 0;
}
