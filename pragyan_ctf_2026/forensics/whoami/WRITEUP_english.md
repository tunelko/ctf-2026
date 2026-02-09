# whoami

**CTF/platform:** Pragyan CTF 2026

**Category:** Forensics / Network Analysis

**Difficulty:** Medium-Hard

**Description:** Identify the user and crack their credentials from network traffic.

**Remote:** N/A (file `capture.pcap`)

**Flag:** `p_ctf{t.stark:Arcadia1451606400}`

---

## Description

We are given a `capture.pcap` file with network traffic. The objective is to find the credentials (`user:pass`) of the user accessing protected resources.

---

## PCAP Analysis

### 1. Initial reconnaissance

```bash
tshark -r capture.pcap -q -z io,phs
```

669KB PCAP with mixed traffic:

| Protocol | Frames | Description |
|-----------|--------|-------------|
| HTTP | 18 | SimpleHTTP/0.6 Python server at 10.1.54.102:8080 |
| SMB2 | 98 | NTLM authentication and shares at 10.1.54.102:445 |
| SSH | 10 | Encrypted traffic (not relevant) |
| Others | ~4500 | Broadcast: IGMP, mDNS, SSDP, NBNS, LLMNR |

### 2. HTTP file extraction

```bash
tshark -r capture.pcap --export-objects http,/tmp/whoami_http/
```

| File | Content | Relevance |
|---------|-----------|------------|
| `policy.txt` | `SECURITY POLICY: Passwords must be [ProjectName][TimestampOfCreation_Epoch].` | **KEY** - Password format |
| `notion.so` | Project list: SuperHeroCallcentre, Terrabound, OceanMining, Arcadia | **KEY** - Project names |
| `admin_log.txt` | 65 lines of server logs, Jan 31 2016 15:02-16:35 UTC | **RED HERRING** |
| `budget.html` | "Meeting Notes: The Avengers initiative is over budget." | Thematic context (Avengers) |
| `menu.txt` | "Lunch Menu: Shawarma, Tacos, Pizza." | Irrelevant |
| `support.txt` | "IT-Support: Try restarting your computer before calling us." | Irrelevant |

### 3. NTLM session identification

Extract all NTLMv2 authentications from SMB2 traffic:

```bash
tshark -r capture.pcap -Y "tcp.port == 445" -T fields \
  -e ntlmssp.auth.username \
  -e ntlmssp.auth.domain \
  -e ntlmssp.ntlmserverchallenge \
  -e ntlmssp.auth.ntresponse
```

**7 NTLM sessions** from **5 users** identified:

| # | User | Server Challenge | Result |
|---|---------|-----------------|-----------|
| 1 | b.banner | `1925b3e5eb7e6970` | Successful login |
| 2 | groot | `07564b444b378633` | Successful login |
| 3 | p.parker | `25a836dcd8bb5c59` | Successful login |
| 4 | hawkeye | `a2504b5506ad986a` | **LOGIN FAILED** (STATUS_LOGON_FAILURE) |
| 5 | hawkeye | `6bd2725dd4b1e524` | Successful login (second attempt) |
| 6 | **t.stark** | `e3ec06e38823c231` | Successful login → accesses `\\SecretPlans` |
| 7 | p.parker | `d7311b515f6e5e64` | Successful login |

**Key observation:** Only `t.stark` accesses the `\\10.1.54.102\SecretPlans` share, confirming this is our target.

### 4. NTLMv2 hash construction for cracking

The NTLMv2 format for hashcat (mode 5600) is:

```
username::domain:server_challenge:NTProofStr:blob
```

Where:
- **NTProofStr** = first 32 hex (16 bytes) of the NT Response
- **blob** = rest of the NT Response
- **domain** = NULL (empty) in this case — **NOT** "SUNLAB-PRECISION-T1650" (server name)

Hash for t.stark:
```
t.stark:::e3ec06e38823c231:977bf57592dc13451d54be92d94a095d:0101000000000000
5c9535bd3c97dc01bd8ada676c80c3180000000002002c005300550...0000000000000000
```

### 5. Methodology verification

Before attacking t.stark's hash, we verify the hashes are correctly extracted by cracking the others with rockyou:

```bash
hashcat -m 5600 all_hashes.txt rockyou-75.txt --force -O
```

**Result:** 5 of 7 hashes cracked → `password123`

| User | Password |
|---------|-----------|
| b.banner | password123 |
| groot | password123 |
| p.parker (x2) | password123 |
| hawkeye (2nd attempt) | password123 |
| hawkeye (1st attempt) | ??? (failed) |
| **t.stark** | ??? |

This confirms:
1. Hashes are correctly extracted ✓
2. t.stark has a different password ✓
3. The `[ProjectName][Epoch]` policy applies to the uncracked hash ✓

### 6. The trap: admin_log timestamps

The `admin_log.txt` has 60+ timestamps from "Jan 31 2016, 15:02-16:35 UTC". The natural temptation is to use these as `TimestampOfCreation_Epoch`.

**Failed attempts:**
```
4 projects × 60 log timestamps = 240 combinations → NOTHING
+ domain variations = 720 → NOTHING
+ timestamps in 2026 = 1440+ → NOTHING
+ project name variations = 10000+ → NOTHING
```

The admin_log timestamps are from **server maintenance activities**, NOT project creation. They are a **red herring**.

### 7. The solution: expand the search range

The key is understanding that "TimestampOfCreation_Epoch" refers to when the **project was created**, not log entries. Project creation might be a "clean" date — like year start, month start, etc.

Generate wordlist covering **all of January 2016** (every hour):

```python
import datetime

projects = ['SuperHeroCallcentre', 'Terrabound', 'OceanMining', 'Arcadia']
passwords = set()

for proj in projects:
    # Complete January 2016, every hour
    for day in range(1, 32):
        for hour in range(24):
            dt = datetime.datetime(2016, 1, day, hour, 0, 0,
                                   tzinfo=datetime.timezone.utc)
            passwords.add(f'{proj}{int(dt.timestamp())}')

    # Full days minute by minute (Jan 31 2016, Jan 31 2026, Feb 6 2026)
    for year, month, day in [(2016,1,31), (2026,1,31), (2026,2,6)]:
        for hour in range(24):
            for minute in range(60):
                dt = datetime.datetime(year, month, day, hour, minute, 0,
                                       tzinfo=datetime.timezone.utc)
                passwords.add(f'{proj}{int(dt.timestamp())}')
```

```bash
hashcat -m 5600 all_hashes.txt wordlist.txt --force -O
```

**Result:**

```
T.STARK:::e3ec06e38823c231:...:Arcadia1451606400
```

### 8. Result decoding

```python
>>> import datetime
>>> datetime.datetime.fromtimestamp(1451606400, tz=datetime.timezone.utc)
datetime.datetime(2016, 1, 1, 0, 0, tzinfo=datetime.timezone.utc)
```

| Field | Value |
|-------|-------|
| Project | **Arcadia** |
| Timestamp | **1451606400** |
| Date | **January 1, 2016, 00:00:00 UTC** |
| Meaning | Midnight at the start of year 2016 |

The password is `Arcadia1451606400`: the **Arcadia** project was created at the beginning of 2016.

---

## Flag

```
p_ctf{t.stark:Arcadia1451606400}
```

---

## Solution Diagram

```
capture.pcap
    │
    ├── HTTP (port 8080)
    │   ├── policy.txt → Format: [ProjectName][TimestampOfCreation_Epoch]
    │   ├── notion.so → Projects: SuperHeroCallcentre, Terrabound,
    │   │                          OceanMining, Arcadia
    │   ├── admin_log.txt → RED HERRING (maintenance timestamps)
    │   └── budget.html, menu.txt, support.txt → Thematic context
    │
    └── SMB2 (port 445) — 7 NTLMv2 sessions
        ├── b.banner, groot, p.parker, hawkeye → password123
        ├── hawkeye (1st attempt) → LOGON_FAILURE
        └── t.stark → Accesses \\SecretPlans → NTLMv2 hash
                          │
                          ├── Extraction: user::domain:challenge:ntproofstr:blob
                          ├── Verification: other 5 hashes = password123 ✓
                          ├── Brute-force with expanded timestamps
                          └── Result: Arcadia + 1451606400 (Jan 1 2016 00:00 UTC)
```

---

## Complete PoC

```python
#!/usr/bin/env python3
"""
whoami - Pragyan CTF 2026
NTLMv2 hash extraction and cracking from PCAP

Flag: p_ctf{t.stark:Arcadia1451606400}

Usage:
  python3 exploit_whoami.py capture.pcap
"""
import subprocess
import datetime
import sys
import os

def extract_ntlmv2_hashes(pcap):
    """Extract NTLMv2 hashes from PCAP in hashcat 5600 format."""
    cmd = (
        f"tshark -r {pcap} -Y 'tcp.port == 445' -T fields "
        f"-e ntlmssp.auth.username -e ntlmssp.auth.domain "
        f"-e ntlmssp.ntlmserverchallenge -e ntlmssp.auth.ntresponse"
    )
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    hashes = []
    challenge = None
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split('\t')
        # Lines with server challenge (NTLMSSP_CHALLENGE)
        if len(parts) >= 3 and parts[2] and not parts[0]:
            challenge = parts[2]
        # Lines with auth data (NTLMSSP_AUTH)
        if len(parts) >= 4 and parts[0] and parts[3]:
            username = parts[0]
            domain = "" if parts[1] == "NULL" else parts[1]
            nt_response = parts[3]
            ntproofstr = nt_response[:32]
            blob = nt_response[32:]
            hashes.append(f"{username}::{domain}:{challenge}:{ntproofstr}:{blob}")

    return hashes

def generate_wordlist():
    """Generate wordlist [ProjectName][EpochTimestamp] for January 2016."""
    projects = ['SuperHeroCallcentre', 'Terrabound', 'OceanMining', 'Arcadia']
    passwords = set()

    for proj in projects:
        # All January 2016, every hour (744 per project)
        for day in range(1, 32):
            for hour in range(24):
                dt = datetime.datetime(2016, 1, day, hour, 0, 0,
                                       tzinfo=datetime.timezone.utc)
                passwords.add(f'{proj}{int(dt.timestamp())}')

        # Jan 31 2016/2026 minute by minute
        for year in [2016, 2026]:
            for hour in range(24):
                for minute in range(60):
                    dt = datetime.datetime(year, 1, 31, hour, minute, 0,
                                           tzinfo=datetime.timezone.utc)
                    passwords.add(f'{proj}{int(dt.timestamp())}')

    return sorted(passwords)

def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"

    print("[*] Step 1: Extracting NTLMv2 hashes...")
    hashes = extract_ntlmv2_hashes(pcap)
    print(f"    {len(hashes)} hashes extracted")

    hash_file = "/tmp/whoami_hashes.txt"
    with open(hash_file, 'w') as f:
        f.write('\n'.join(hashes) + '\n')

    print("[*] Step 2: Generating wordlist...")
    passwords = generate_wordlist()
    wordlist_file = "/tmp/whoami_wordlist.txt"
    with open(wordlist_file, 'w') as f:
        f.write('\n'.join(passwords) + '\n')
    print(f"    {len(passwords)} passwords generated")

    print("[*] Step 3: Cracking with hashcat (mode 5600)...")
    subprocess.run(
        f"hashcat -m 5600 {hash_file} {wordlist_file} --force -O --quiet",
        shell=True
    )

    print("\n[*] Results:")
    result = subprocess.run(
        f"hashcat -m 5600 {hash_file} --show",
        shell=True, capture_output=True, text=True
    )

    for line in result.stdout.strip().split('\n'):
        if line:
            parts = line.split(':')
            user = parts[0]
            password = parts[-1]
            print(f"    {user}: {password}")
            if 't.stark' in user.lower():
                print(f"\n[★] FLAG: p_ctf{{{user.lower()}:{password}}}")

if __name__ == "__main__":
    main()
```

---

## Tools Used

- **tshark** — PCAP analysis and NTLM field extraction
- **hashcat** (mode 5600) — NTLMv2 hash cracking
- **Python 3** — Wordlist generation and automation

---

## Lessons Learned

1. **Don't trust the most visible timestamps**: The 60+ timestamps in admin_log were server maintenance. The "project creation" timestamp was a clean date: January 1, 2016 (epoch 1451606400).

2. **Verify methodology with easy hashes**: Cracking the other 5 users with `password123` first confirmed that hash extraction and format were correct.

3. **The domain field in NTLMv2 matters**: The domain was NULL/empty in NTLMSSP_AUTH, not "SUNLAB-PRECISION-T1650" (server Target name). An error here would have invalidated all cracking.

4. **Expand search space systematically**: Instead of guessing specific timestamps, covering all January 2016 every hour (744 timestamps × 4 projects = ~3000 candidates) was fast and effective.

5. **NTLMv2 ≠ NTLM**: NTLMv2 is challenge-response (unique per session). Cannot search online databases like CrackStation. Requires brute-force with hashcat/john.
