#!/usr/bin/env python3
"""DawgCTF 2026 - Data Needs Splitting (rev) - DNS TXT → JAR → XOR reverse"""
import subprocess, base64

# 1. Extract base64 from DNS TXT records
result = subprocess.run(["dig", "data-needs-splitting.umbccd.net", "TXT", "+short"],
                       capture_output=True, text=True)
records = {}
for line in result.stdout.strip().split("\n"):
    txt = line.strip('"')
    records[txt[:2]] = txt[2:]
b64 = "".join(records[k] for k in sorted(records, key=lambda x: int(x)))
with open("dns_file.jar", "wb") as f:
    f.write(base64.b64decode(b64))

# 2. Reverse the XOR validation from Validator.class
Key1 = 2194307438957234483
Key2 = 148527584754938272
keys = [(((Key1 >> (i*16)) & 0xFFFF) ^ ((Key2 >> (i*16)) & 0xFFFF)) for i in range(4)]

target = "145511939249997195145441944550467175145531942549987228145401943650017203145451934650207244145651934650127169"

def solve(target, keys, pos=0, idx=0, result=[]):
    if pos == len(target):
        return "".join(result)
    for length in range(1, 6):
        if pos + length > len(target): break
        s = target[pos:pos+length]
        if s[0] == '0' and length > 1: continue
        ch = int(s) ^ keys[idx % 4]
        if 32 <= ch <= 126:
            result.append(chr(ch))
            if sol := solve(target, keys, pos+length, idx+1, result): return sol
            result.pop()
    return None

print(f"Flag: {solve(target, keys)}")
