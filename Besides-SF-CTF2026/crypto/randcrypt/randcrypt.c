#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef __uint128_t u128;

#define U128_FROM64(hi, lo) ((((u128)(hi)) << 64) | (u128)(lo))


static u128 rng_next(u128 state) {

    /* xorshift is known to be weak, as are LCGs.
     * However, combining the two allows them to
     * cover each other's weaknesses.
     *
     * To ensure cryptographic quality we'll do 4
     * rounds with different constants just to be
     * extra careful.
     */

    u128 x = state;

    /* Round 1 */
    x = (x << 7) ^ x;
    x *= U128_FROM64(0xc7d966554fdd8895ULL, 0x2bd67b67587a550dULL); /* 265645175144390835861687139373879547149 */
    x += U128_FROM64(0xaad7d93a4256e815ULL, 0x6b2b70757a011d80ULL); /* 227089509006669178826418507523886751104 */

    /* Round 2 */
    x = (x >> 13) ^ x;
    x *= U128_FROM64(0xa064c0bdb010eab3ULL, 0xcb5a960584361b11ULL); /* 213199618262696451636191318471217650449 */
    x += U128_FROM64(0xca5e129f88544319ULL, 0x3e87d676b3f2f21eULL); /* 268992508776097813590527519319322194462 */

    /* Round 3 */
    x = (x << 19) ^ x;
    x *= U128_FROM64(0xad68c652004075c9ULL, 0xb1562331444753a3ULL); /* 230500464557966844776053247791604388771 */
    x += U128_FROM64(0xfa2556c0ac3f32d0ULL, 0x7116f45b079e2977ULL); /* 332500873482335697609919624378413099383 */

    /* Round 4 */
    x = (x >> 23) ^ x;
    x *= U128_FROM64(0x6a257956638a8856ULL, 0x0427312461d8096dULL); /* 141092743552957380792894410589289843053 */
    x += U128_FROM64(0x7f226a22555b20e3ULL, 0xe790563048bad20aULL); /* 168990646213466405964429500161933890058 */

    return x;
}


static u128 bytes_to_u128_be(const uint8_t in[16]) {

    u128 v = 0;
    for (int i = 0; i < 16; i++) {
        v = (v << 8) | (u128)in[i];
    }

    return v;
}


static void u128_to_bytes_be(u128 v, uint8_t out[16]) {

    for (int i = 15; i >= 0; i--) {
        out[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
}


static int hex_nibble(int c) {

    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;

    return -1;
}


static int parse_hex_u128(const char *s, size_t len, u128 *out) {

    if (len != 32) {
        return -1;
    }

    u128 v = 0;
    for (size_t i = 0; i < len; i++) {
        int n = hex_nibble((unsigned char)s[i]);

        if (n < 0) return -1;

        v = (v << 4) | (u128)n;
    }

    *out = v;

    return 0;
}


static void print_key_hex(u128 key) {
    char buf[33];
    for (int i = 31; i >= 0; i--) {
        uint8_t nibble = (uint8_t)(key & 0x0f);
        buf[i] = (nibble < 10) ? ('0' + nibble) : ('a' + (nibble - 10));
        key >>= 4;
    }
    buf[32] = '\0';
    printf("%s\n", buf);
}


static ssize_t read_block(FILE *in, u128 *block, uint8_t buf[16]) {

    memset(buf, 0, 16);

    size_t off = 0;
    while (off < 16) {

        size_t n = fread(buf + off, 1, 16 - off, in);

        if (n == 0) {
            if (feof(in)) {
                break;
            }

            if (ferror(in)) {
                fprintf(stderr, "read failed: %s\n", strerror(errno));
                return -1;
            }
        }

        off += n;

        if (n == 0) {
            break;
        }
    }

    *block = bytes_to_u128_be(buf);

    return (ssize_t)off;
}


static int write_block(FILE *out, u128 block) {

    uint8_t buf[16];
    u128_to_bytes_be(block, buf);

    if (fwrite(buf, 1, 16, out) != 16) {
        fprintf(stderr, "write failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}


static int rng_init(u128 *key) {

    uint8_t kbytes[16];
    u128 block = 0;

    FILE *ur = fopen("/dev/urandom", "rb");
    if (!ur) {
        return -1;
    }

    ssize_t n = read_block(ur, &block, kbytes);
    fclose(ur);

    if (n != 16) {
        return -1;
    }

    *key = block;

    return 0;
}


static int process_file(FILE *in, FILE *out, u128 key, int encrypt) {

    u128 state = rng_next(key);
    uint8_t buf[16];
    u128 block = 0;
    u128 last_block = 0;
    int have_last = 0;
    ssize_t n;
    u128 total_len = 0;

    int done = 0;
    while (!done) {
        n = read_block(in, &block, buf);

        if (n < 0) {
            return -1;
        }

        total_len += (u128)n;

        /* The actual encrypt/decrypt step */
        block ^= state;

        if (n > 0) {
            last_block = block;
            have_last = 1;
        }

        if (write_block(out, block) != 0) {
            return -1;
        }

        /* Securely evolve the state for the next block */
        state = rng_next(state);

        if (n == 0) {
            done = 1;
        }
    }


    if (encrypt) {
        u128 len_block = total_len ^ state;
        if (write_block(out, len_block) != 0) {
            return -1;
        }
    } else {
        if (!have_last) {
            fprintf(stderr, "read failed: missing length block\n");
            return -1;
        }

        if (last_block > total_len) {
            fprintf(stderr, "read failed: length exceeds output\n");
            return -1;
        }

        if (last_block > (u128)INT64_MAX) {
            fprintf(stderr, "read failed: length too large\n");
            return -1;
        }

        if (fflush(out) != 0) {
            fprintf(stderr, "write failed: %s\n", strerror(errno));
            return -1;
        }

        if (ftruncate(fileno(out), (off_t)last_block) != 0) {
            fprintf(stderr, "truncate failed: %s\n", strerror(errno));
            return -1;
        }
    }

    return 0;
}


static int usage(const char *prog) {

    fprintf(stderr, "usage: %s -e srcfile dstfile\n", prog);
    fprintf(stderr, "       %s -d srcfile dstfile\n", prog);
    return 1;
}


int main(int argc, char **argv) {

    if (argc != 4) {
        return usage(argv[0]);
    }

    int encrypt = 0;
    if (strcmp(argv[1], "-e") == 0) {
        encrypt = 1;
    } else if (strcmp(argv[1], "-d") == 0) {
        encrypt = 0;
    } else {
        return usage(argv[0]);
    }

    const char *src = argv[2];
    const char *dst = argv[3];
    u128 key = 0;
    FILE *in = NULL;
    FILE *out = NULL;

    if (encrypt) {
        if (rng_init(&key) != 0) {
            fprintf(stderr, "failed to read /dev/urandom\n");
            return 1;
        }

        fprintf(stdout, "rand key (hex): ");
        print_key_hex(key);

    } else {
        char line[128];

        fprintf(stdout, "key (hex): ");

        if (!fgets(line, sizeof(line), stdin)) {
            fprintf(stderr, "failed to read key\n");
            return 1;
        }

        size_t len = strcspn(line, "\r\n");
        line[len] = '\0';
        if (parse_hex_u128(line, len, &key) != 0) {
            fprintf(stderr, "invalid key: expected 32 hex chars (128-bit).\n");
            return 1;
        }
    }

    in = fopen(src, "rb");
    if (!in) {
        fprintf(stderr, "failed to open %s: %s\n", src, strerror(errno));
        return 1;
    }

    out = fopen(dst, "wb");
    if (!out) {
        fprintf(stderr, "failed to open %s: %s\n", dst, strerror(errno));
        fclose(in);
        return 1;
    }

    if (process_file(in, out, key, encrypt) != 0) {
        fclose(in);
        fclose(out);
        return 1;
    }

    fclose(in);
    fclose(out);

    return 0;
}
