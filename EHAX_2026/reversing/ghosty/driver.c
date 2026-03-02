// driver.c - C driver that replicates the Lua callbacks and calls entry()
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>

// Tables (will be loaded from decoded tables_blob.bin)
static uint32_t MIX_TABLE[256];
static uint8_t POLICY_TABLE[256];
static uint8_t SCRAMBLE_KEY[32];

static uint8_t nonce[32];
static void init_nonce(void) {
    nonce[0]=0x3A; nonce[1]=0x7F; nonce[2]=0x21; nonce[3]=0x88;
    nonce[4]=0xC0; nonce[5]=0x4B; nonce[6]=0xE3; nonce[7]=0x11;
    nonce[8]=0x9D; nonce[9]=0x56; nonce[10]=0xA2; nonce[11]=0x0F;
    nonce[12]=0x73; nonce[13]=0xBC; nonce[14]=0x48; nonce[15]=0x2E;
    nonce[16]=0x61; nonce[17]=0xD4; nonce[18]=0x97; nonce[19]=0x3C;
    nonce[20]=0x85; nonce[21]=0xFA; nonce[22]=0x1E; nonce[23]=0x50;
    nonce[24]=0xAD; nonce[25]=0x79; nonce[26]=0x02; nonce[27]=0xC6;
    nonce[28]=0x38; nonce[29]=0xEF; nonce[30]=0x6B; nonce[31]=0x14;
}

static void load_tables(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("tables_blob.bin"); exit(1); }
    uint8_t raw[1312];
    fread(raw, 1, 1312, f);
    fclose(f);

    uint8_t decoded[1312];
    for (int i = 0; i < 1312; i++)
        decoded[i] = raw[i] ^ nonce[i % 32];

    for (int i = 0; i < 256; i++) {
        int off = i * 4;
        MIX_TABLE[i] = (uint32_t)decoded[off]
                      | ((uint32_t)decoded[off+1] << 8)
                      | ((uint32_t)decoded[off+2] << 16)
                      | ((uint32_t)decoded[off+3] << 24);
    }

    memcpy(POLICY_TABLE, decoded + 1024, 256);
    memcpy(SCRAMBLE_KEY, decoded + 1280, 32);
}

static uint32_t ror32(uint32_t val, unsigned n) {
    n %= 32;
    return (val >> n) | (val << (32 - n));
}

static uint32_t cb_mix32(uint32_t a, uint32_t b) {
    uint8_t ai = a & 0xFF;
    uint8_t bi = b & 0xFF;
    uint32_t m = MIX_TABLE[ai ^ bi];
    uint32_t x = a ^ m;
    x ^= ror32(b, 7);
    x ^= MIX_TABLE[(a >> 8) & 0xFF];
    return x;
}

static void cb_scramble(uint8_t *buf, size_t n, uint32_t seed) {
    uint32_t ks = (seed ^ 0x5A3C9F11) & 0xFFFFFFFF;
    for (size_t i = 0; i < n; i++) {
        uint8_t ki = SCRAMBLE_KEY[ks & 0x1F];
        buf[i] ^= ki;
        ks ^= (ks << 13);
        ks &= 0xFFFFFFFF;
        ks ^= (ks >> 17);
        ks &= 0xFFFFFFFF;
        ks ^= (ks << 5);
        ks &= 0xFFFFFFFF;
    }
}

static uint32_t cb_get_salt(void) {
    return 0x13371337;
}

static uint32_t cb_policy(uint32_t q) {
    uint8_t lo = q & 0xFF;
    uint8_t hi = (q >> 8) & 0xFF;
    uint8_t p = POLICY_TABLE[lo ^ hi];
    return q ^ ((uint32_t)p << 8);
}

static void cb_log(const char *s) {
    // no-op
}

// Packed API struct matching the Lua definition
typedef struct __attribute__((packed)) {
    uint32_t abi_version;
    uint32_t (*mix32)(uint32_t a, uint32_t b);
    void     (*scramble)(uint8_t *buf, size_t n, uint32_t seed);
    uint32_t (*get_salt)(void);
    uint32_t (*policy)(uint32_t q);
    void     (*log)(const char *s);
} API;

typedef int (*entry_fn)(const API *, const uint8_t *, size_t);

int main(int argc, char *argv[]) {
    init_nonce();
    load_tables("tables_blob.bin");

    void *lib = dlopen("./libruntime.so", RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }

    entry_fn entry = (entry_fn)dlsym(lib, "entry");
    if (!entry) {
        fprintf(stderr, "dlsym: %s\n", dlerror());
        return 1;
    }

    API api;
    api.abi_version = 1;
    api.mix32 = cb_mix32;
    api.scramble = cb_scramble;
    api.get_salt = cb_get_salt;
    api.policy = cb_policy;
    api.log = cb_log;

    uint8_t input[32] = {0};
    const char *inp_str = "AAAA";
    if (argc > 1) inp_str = argv[1];
    size_t len = strlen(inp_str);
    if (len > 32) len = 32;
    memcpy(input, inp_str, len);

    fprintf(stderr, "[*] Calling entry() with input: '%s'\n", inp_str);
    int result = entry(&api, input, 32);
    fprintf(stderr, "[*] entry() returned: %d\n", result);

    return result <= 0 ? 1 : 0;
}
