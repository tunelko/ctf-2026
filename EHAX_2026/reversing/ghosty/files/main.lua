local ffi = require("ffi")
local bit = require("bit")

ffi.cdef[[
typedef struct __attribute__((packed)) {
    uint32_t abi_version;
    uint32_t (*mix32)(uint32_t a, uint32_t b);
    void     (*scramble)(uint8_t *buf, size_t n, uint32_t seed);
    uint32_t (*get_salt)(void);
    uint32_t (*policy)(uint32_t q);
    void     (*log)(const char *s);
} API;

int entry(const API *api, const uint8_t *input, size_t n);
]]

local function dirname(path)
    local d = path:match("^(.*)[/\\][^/\\]+$")
    if not d or d == "" then
        return "."
    end
    return d
end

local SCRIPT_DIR = dirname(arg and arg[0] or "./main.lua")

local function first_existing(paths)
    for _, p in ipairs(paths) do
        local f = io.open(p, "rb")
        if f then
            f:close()
            return p
        end
    end
    return nil
end

local function load_tables()
    local n1 = "\x3A\x7F\x21\x88\xC0\x4B\xE3\x11"
    local n2 = "\x9D\x56\xA2\x0F\x73\xBC\x48\x2E"
    local n3 = "\x61\xD4\x97\x3C\x85\xFA\x1E\x50"
    local n4 = "\xAD\x79\x02\xC6\x38\xEF\x6B\x14"
    local nonce = n1 .. n2 .. n3 .. n4

    local blob_path = first_existing({
        SCRIPT_DIR .. "/tables_blob.bin",
        "./tables_blob.bin",
    })
    assert(blob_path, "tables_blob.bin not found")

    local f = assert(io.open(blob_path, "rb"))
    local raw = f:read("*a")
    f:close()

    local decoded = {}
    for i = 1, #raw do
        decoded[i] = bit.bxor(raw:byte(i), nonce:byte(((i - 1) % 32) + 1))
    end

    local MIX_TABLE = {}
    for i = 0, 255 do
        local off = i * 4 + 1
        MIX_TABLE[i] = bit.tobit(
            bit.bor(
                decoded[off],
                bit.lshift(decoded[off + 1], 8),
                bit.lshift(decoded[off + 2], 16),
                bit.lshift(decoded[off + 3], 24)
            )
        )
    end

    local POLICY_TABLE = {}
    for i = 0, 255 do
        POLICY_TABLE[i] = decoded[1024 + i + 1]
    end

    local SCRAMBLE_KEY = {}
    for i = 0, 31 do
        SCRAMBLE_KEY[i] = decoded[1280 + i + 1]
    end

    return MIX_TABLE, POLICY_TABLE, SCRAMBLE_KEY
end

local MIX_TABLE, POLICY_TABLE, SCRAMBLE_KEY = load_tables()

local CB = {}

CB.mix32 = ffi.cast("uint32_t(*)(uint32_t,uint32_t)", function(a, b)
    local ai = bit.band(a, 0xFF)
    local bi = bit.band(b, 0xFF)
    local m = MIX_TABLE[bit.bxor(ai, bi)]
    local x = bit.bxor(a, m)
    x = bit.bxor(x, bit.ror(b, 7))
    x = bit.bxor(x, MIX_TABLE[bit.band(bit.rshift(a, 8), 0xFF)])
    return bit.tobit(x)
end)

CB.scramble = ffi.cast("void(*)(uint8_t*,size_t,uint32_t)", function(buf, n, seed)
    local ks = bit.band(bit.bxor(seed, 0x5A3C9F11), 0xFFFFFFFF)
    local nn = tonumber(n)
    for i = 0, nn - 1 do
        local ki = SCRAMBLE_KEY[bit.band(ks, 0x1F)]
        buf[i] = bit.band(bit.bxor(buf[i], ki), 0xFF)
        ks = bit.band(bit.bxor(ks, bit.lshift(ks, 13)), 0xFFFFFFFF)
        ks = bit.band(bit.bxor(ks, bit.rshift(ks, 17)), 0xFFFFFFFF)
        ks = bit.band(bit.bxor(ks, bit.lshift(ks, 5)), 0xFFFFFFFF)
    end
end)

CB.get_salt = ffi.cast("uint32_t(*)(void)", function()
    return 0x13371337
end)

CB.policy = ffi.cast("uint32_t(*)(uint32_t)", function(q)
    local lo = bit.band(q, 0xFF)
    local hi = bit.band(bit.rshift(q, 8), 0xFF)
    local p = POLICY_TABLE[bit.bxor(lo, hi)]
    return bit.tobit(bit.bxor(q, bit.lshift(p, 8)))
end)

CB.log = ffi.cast("void(*)(const char*)", function(_)
end)

local function load_runtime()
    local candidates = {
        SCRIPT_DIR .. "/libruntime.so",
        "./libruntime.so",
        SCRIPT_DIR .. "/../runtime/target/release/libruntime.so",
    }

    for _, p in ipairs(candidates) do
        local ok, lib = pcall(ffi.load, p)
        if ok and lib then
            return lib
        end
    end

    error("could not load libruntime.so")
end

local rt = load_runtime()

local api = ffi.new("API")
api.abi_version = 1
api.mix32 = CB.mix32
api.scramble = CB.scramble
api.get_salt = CB.get_salt
api.policy = CB.policy
api.log = CB.log

local input_str = (arg and arg[1]) or io.read("*l") or ""
local n = math.min(#input_str, 32)
local inp = ffi.new("uint8_t[32]")
for i = 0, n - 1 do
    inp[i] = input_str:byte(i + 1)
end

local result = rt.entry(api, inp, 32)
if result <= 0 then
    io.stderr:write("Wrong.\n")
    os.exit(1)
end
