#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define NUM_GROUPS 287
#define ROUNDS 1000

static uint32_t targets[NUM_GROUPS];
static uint8_t result[NUM_GROUPS * 3 + 1];
static int done_count = 0;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

static inline uint32_t hash_group(uint8_t b0, uint8_t b1, uint8_t b2, uint32_t ebx_in) {
    uint32_t ecx = ((uint32_t)b0 << 16) | ((uint32_t)b1 << 8) | b2;
    ecx ^= ebx_in;
    uint32_t ebp = ecx;
    for (int i = 0; i < ROUNDS; i++) {
        ecx ^= (ecx << 13);
        ecx ^= (ecx >> 17);
        ecx ^= (ecx << 5);
        ecx *= 0x2545f491U;
    }
    return ecx ^ ebp;
}

/* Sequential solve: each group depends on previous ebx */
int main() {
    FILE *f = fopen("targets.bin", "rb");
    if (!f) { perror("targets.bin"); return 1; }
    fread(targets, 4, NUM_GROUPS, f);
    fclose(f);

    uint32_t ebx = 0xdeadbeef;
    memset(result, 0, sizeof(result));

    for (int g = 0; g < NUM_GROUPS; g++) {
        int found = 0;
        /* Try printable ASCII first (fast) */
        for (int b0 = 0x0a; b0 < 0x7f && !found; b0++) {
            /* Skip non-printable except \n(0x0a), \r(0x0d) */
            if (b0 > 0x0d && b0 < 0x20) continue;
            for (int b1 = 0x0a; b1 < 0x7f && !found; b1++) {
                if (b1 > 0x0d && b1 < 0x20) continue;
                for (int b2 = 0x0a; b2 < 0x7f && !found; b2++) {
                    if (b2 > 0x0d && b2 < 0x20) continue;
                    uint32_t res = hash_group(b0, b1, b2, ebx);
                    if (res == targets[g]) {
                        result[g*3] = b0;
                        result[g*3+1] = b1;
                        result[g*3+2] = b2;
                        ebx = res;
                        found = 1;
                    }
                }
            }
        }
        if (!found) {
            /* Full range fallback */
            for (int b0 = 0; b0 < 256 && !found; b0++) {
                for (int b1 = 0; b1 < 256 && !found; b1++) {
                    for (int b2 = 0; b2 < 256 && !found; b2++) {
                        uint32_t res = hash_group(b0, b1, b2, ebx);
                        if (res == targets[g]) {
                            result[g*3] = b0;
                            result[g*3+1] = b1;
                            result[g*3+2] = b2;
                            ebx = res;
                            found = 1;
                        }
                    }
                }
            }
        }
        if (found) {
            if (g < 10 || g % 50 == 0 || g == NUM_GROUPS - 1)
                fprintf(stderr, "Group %3d/%d: 0x%02x 0x%02x 0x%02x\n",
                        g, NUM_GROUPS, result[g*3], result[g*3+1], result[g*3+2]);
        } else {
            fprintf(stderr, "Group %d: NOT FOUND!\n", g);
            break;
        }
    }

    /* Print result */
    result[NUM_GROUPS * 3] = 0;
    printf("%s\n", result);
    return 0;
}
