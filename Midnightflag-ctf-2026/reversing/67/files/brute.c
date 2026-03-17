#include <stdio.h>
#include <stdint.h>

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
    uint32_t expected[4] = {0x29a5b7cc, 0xd0e8a4e7, 0x5f5ec278, 0x0e9bff41};
    uint32_t ebx = 0xdeadbeef;
    uint8_t result[12];

    for (int group = 0; group < 4; group++) {
        int found = 0;
        for (int b0 = 0x20; b0 < 0x7f && !found; b0++) {
            for (int b1 = 0x20; b1 < 0x7f && !found; b1++) {
                for (int b2 = 0x20; b2 < 0x7f && !found; b2++) {
                    uint32_t res = hash_group(b0, b1, b2, ebx);
                    if (res == expected[group]) {
                        result[group*3] = b0;
                        result[group*3+1] = b1;
                        result[group*3+2] = b2;
                        ebx = res;
                        found = 1;
                        fprintf(stderr, "Group %d: '%c%c%c' (0x%02x 0x%02x 0x%02x) -> 0x%08x\n",
                                group, b0, b1, b2, b0, b1, b2, res);
                    }
                }
            }
        }
        if (!found) {
            fprintf(stderr, "Group %d: NOT FOUND in printable ASCII\n", group);
            // Try full byte range
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
                            fprintf(stderr, "Group %d: 0x%02x 0x%02x 0x%02x -> 0x%08x\n",
                                    group, b0, b1, b2, res);
                        }
                    }
                }
            }
        }
    }

    printf("Flag: %.12s\n", result);
    return 0;
}
