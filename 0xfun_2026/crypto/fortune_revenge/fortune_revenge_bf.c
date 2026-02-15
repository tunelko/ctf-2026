#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s g1 g2 g3\n", argv[0]);
        return 1;
    }

    uint32_t g1 = (uint32_t)strtoul(argv[1], NULL, 10);
    uint32_t g2 = (uint32_t)strtoul(argv[2], NULL, 10);
    uint32_t g3 = (uint32_t)strtoul(argv[3], NULL, 10);

    /* LCG parameters */
    uint64_t M_mask = 0xFFFFFFFFFFFFFFFFULL; /* 2^64 - 1, wraps naturally */
    uint64_t A = 2862933555777941757ULL;
    uint64_t C = 3037000493ULL;
    uint64_t A_JUMP = 3297373631046652033ULL; /* pow(A, 100000, 2^64) */
    uint64_t C_JUMP = 8391006422427229792ULL;

    /* Effective LCG: combines jump() + next() */
    /* state3 = A * (A_JUMP * state1 + C_JUMP) + C */
    /* state3 = (A * A_JUMP) * state1 + (A * C_JUMP + C) */
    uint64_t A_TOTAL = A * A_JUMP; /* mod 2^64 automatic */
    uint64_t C_TOTAL = A * C_JUMP + C;

    fprintf(stderr, "A_TOTAL = %llu\n", (unsigned long long)A_TOTAL);
    fprintf(stderr, "C_TOTAL = %llu\n", (unsigned long long)C_TOTAL);
    fprintf(stderr, "Searching for state with g1=%u g2=%u g3=%u\n", g1, g2, g3);

    uint64_t high1 = (uint64_t)g1 << 32;

    for (uint64_t low1 = 0; low1 < 0x100000000ULL; low1++) {
        uint64_t state1 = high1 | low1;
        uint64_t state3 = A_TOTAL * state1 + C_TOTAL;

        if ((state3 >> 32) == g2) {
            uint64_t state5 = A_TOTAL * state3 + C_TOTAL;
            if ((state5 >> 32) == g3) {
                fprintf(stderr, "FOUND! state1=%llu state3=%llu state5=%llu\n",
                        (unsigned long long)state1,
                        (unsigned long long)state3,
                        (unsigned long long)state5);
                /* Print the next 5 states (regular next(), no jump) */
                uint64_t s = state5;
                for (int i = 0; i < 5; i++) {
                    s = A * s + C;
                    printf("%llu", (unsigned long long)s);
                    if (i < 4) printf(" ");
                }
                printf("\n");
                return 0;
            }
        }
    }

    fprintf(stderr, "NOT FOUND\n");
    return 1;
}
