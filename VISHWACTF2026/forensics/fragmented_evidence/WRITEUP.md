# Fragmented Evidence

**CTF**: VishwaCTF 2026
**Category**: Forensics
**Flag**: `VishwaCTF{ObfuscatedTruth}`

## TL;DR

Server log with base64 fragments hidden in anomaly IDs and error codes. Concatenate and decode.

## Analysis

`server.log` contains normal-looking log entries. Several `WARN: packet anomaly detected id=` and one `ERROR: backup failed code=` entry contain base64 fragments:

```
id=Zmxh → fla
id=Z3tP → g{O
id=YmZ1 → bfu
id=c2Nh → sca
id=dGVk → ted
code=VHJ1dGh9 → Truth}
```

## Solution

```bash
grep -oP 'id=\K\S+|code=\K\S+' server.log | tr -d '\n' | base64 -d
# ZmxhZ3tPYmZ1c2NhdGVkVHJ1dGh9 → flag{ObfuscatedTruth}
```

Flag format: `VishwaCTF{ObfuscatedTruth}`

## Files

- `server.log` — Challenge log file
- `flag.txt` — Captured flag
