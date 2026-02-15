# kd> — Forensics (50 pts)

**CTF:** 0xFun CTF 2026
**Category:** Forensics
**Difficulty:** Beginner
**Author:** N!L
**Flag:** `0xfun{wh0_n33ds_sl33p_wh3n_y0u_h4v3_cr4sh_dumps}`

---

## Description

> something crashed. something was left behind.

4 files are provided:
- `crypter.dmp` — Windows Mini DuMP (425 MB)
- `config.dat` — 256 bytes of binary data
- `events.xml` — Windows event log (303 KB)
- `transcript.enc` — Encrypted transcript (23 KB)

## Analysis

### 1. Identify the crash dump

```bash
file crypter.dmp
# Mini DuMP crash report, 6 streams, Fri Feb 10 ...
```

The dump is from `crypter.exe` (CrypterService), an encryption service that crashed with `EXCEPTION_ACCESS_VIOLATION` (null pointer dereference).

### 2. Service context

From the dump and events.xml, the configuration is extracted:

```ini
[Encryption]
Algorithm=AES-256-CBC
KeyDerivation=SHA256
KeyShards=2
ConfigPath=config.dat
```

events.xml contains 320+ CrypterService events: KeyNegotiation, KeyRotation, KeyDerivation, SessionInit, etc. The session tokens are an arithmetic sequence (+0x13 per byte) — red herring.

### 3. Search for the flag in memory

The challenge hint is key: "something was left behind". When crashing, the process left all its memory in the dump. The flag is directly in the process heap:

```python
with open('crypter.dmp', 'rb') as f:
    data = f.read()
    idx = data.find(b'0xfun{')
    end = data.find(b'}', idx)
    print(data[idx:end+1])
```

### 4. Flag found

At offset `0x1640dea8` in the dump:

```
0x1640dea8: 0xfun{wh0_n33ds_sl33p_wh3n_y0u_h4v3_cr4sh_dumps}
```

Surrounded by author strings:
- `N!L?BRRR_v3_CTF`
- `N!L?_CONFIG_OK!!`
- Anomalous token `5bd2871ef364a90c46ce387ae1950db6`

## Solution

The key was simply searching for strings in the crash dump. The files `config.dat`, `events.xml`, and `transcript.enc` are elaborate distractions (or part of an extended challenge).

```bash
strings crypter.dmp | grep "0xfun{"
# or direct binary search with Python/grep
```

## Tools

- `file` — identify the file type
- Python (`minidump`) — parse the dump
- `strings` / binary search — find the flag in memory
