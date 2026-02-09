# Follow The Sequence - CTF Writeup

## Challenge Description

> We are trying to improve resource utilisation by spreading data across several subflows. We needed to install a new kernel module, but the speed upgrade is worth it! Can you combine requests and recover the flag?

**Provided file:** `24ec9b75de3c273d2765622deb3c7f742b87cf6b.zip`

---

## Tools Used

- `tshark` - Network packet analysis
- `xxd` - Hexadecimal conversion
- `unzip` - File extraction

---

## Key Concepts: MPTCP

**Multipath TCP (MPTCP)** is an extension of the TCP protocol that allows:
- Using multiple network paths simultaneously
- Distributing data across several "subflows"
- Each subflow has its own TCP sequence
- A global **Data Sequence Number (DSN)** orders the data

The challenge mentions "kernel module" because MPTCP requires kernel-level support.

---

## Step 1: Extraction and Reconnaissance

```bash
unzip 24ec9b75de3c273d2765622deb3c7f742b87cf6b.zip
```

**Contents:**
```
chall-i1.pcap   (7.4 MB)  - Subflow 1
chall-i2.pcap  (22.9 MB)  - Subflow 2
chall-i3.pcap  (15.8 MB)  - Subflow 3
```

---

## Step 2: Subflow Analysis

```bash
for f in *.pcap; do
  echo "=== $f ==="
  tshark -r "$f" 2>/dev/null | head -5
done
```

**Result:**
```
=== chall-i1.pcap ===
10.1.1.2 → 10.1.1.3  MPTCP 80 → 54072 [SYN, ACK]

=== chall-i2.pcap ===
10.1.2.2 → 10.1.2.3  MPTCP 80 → 41187 [SYN, ACK]

=== chall-i3.pcap ===
10.1.3.2 → 10.1.3.3  MPTCP 80 → 42877 [SYN, ACK]
```

**Observations:**
- Three MPTCP subflows on different subnets (10.1.1.x, 10.1.2.x, 10.1.3.x)
- All from port 80 (HTTP)
- Data is distributed across the three paths

---

## Step 3: MPTCP Data Extraction

### Important MPTCP Fields

| Field | Description |
|-------|-------------|
| `tcp.options.mptcp.rawdataseqno` | Data Sequence Number (DSN) - global position |
| `tcp.options.mptcp.datalvllen` | Data length |
| `tcp.payload` | Payload in hexadecimal |

### Extraction from Each Subflow

```bash
for f in chall-i1.pcap chall-i2.pcap chall-i3.pcap; do
  tshark -r "$f" -T fields \
    -e tcp.options.mptcp.rawdataseqno \
    -e tcp.options.mptcp.datalvllen \
    -e tcp.payload 2>/dev/null \
    | grep -v "^$" > "${f%.pcap}_data.txt"
done
```

**Result:**
```
chall-i1_data.txt:  4,835 fragments
chall-i2_data.txt: 14,940 fragments
chall-i3_data.txt: 10,287 fragments
```

### Extracted Data Format

```
DSN             Length  Payload (hex)
3663086631      1428    485454502f312e31203230...
3663088059      1428    ffd8ffe000104a46494600...
3663089487      1428    ...
```

---

## Step 4: Recombination by DSN

The **Data Sequence Number (DSN)** indicates the absolute position of each fragment in the complete data stream. By sorting by DSN and concatenating, we reconstruct the original file.

```bash
cat chall-i1_data.txt chall-i2_data.txt chall-i3_data.txt \
  | sort -t'	' -k1,1n \
  | cut -f3 \
  | tr -d ':' \
  | xxd -r -p > combined.bin
```

**Result:** `combined.bin` (42.9 MB)

---

## Step 5: Combined File Analysis

```bash
xxd combined.bin | head -20
```

```
00000000: 4854 5450 2f31 2e31 2032 3030 204f 4b0d  HTTP/1.1 200 OK.
00000010: 0a44 6174 653a 2046 7269 2c20 3130 2041  .Date: Fri, 10 A
...
000000e0: 2061 7070 6c69 6361 7469 6f6e 2f7a 6970   application/zip
000000f0: 0d0a 0d0a 504b 0304 1400 0000 0000 6155  ....PK........aU
```

**Findings:**
- HTTP 200 OK response
- Content-Type: application/zip
- ZIP file starts at offset 244 (`PK` signature)

---

## Step 6: ZIP Extraction

```bash
# Skip HTTP header (244 bytes)
dd if=combined.bin bs=1 skip=244 of=extracted.zip

# Verify contents
unzip -l extracted.zip
```

**ZIP Contents:**
```
  Length      Name
---------     ----
        0     flag/
 13182786     flag/ALSO_NOT_A_FLAG.jpg
   109817     flag/Flag.jpg
   119380     flag/Here.jpg
   109221     flag/Is.jpg
  1611708     flag/NOT_A_FLAG.jpg
  2119781     flag/NOT_FLAG.jpg
  4088390     flag/NOT_THE_FLAG.jpg
 14488498     flag/NO_FLAG.jpg
  6304080     flag/NO_FLAG_HERE.jpg
   109502     flag/The.jpg
```

**Suspicious files:** `The.jpg`, `Flag.jpg`, `Is.jpg`, `Here.jpg` (forming "The Flag Is Here")

---

## Step 7: Flag Extraction

```bash
unzip extracted.zip "flag/Here.jpg"
```

When viewing `Here.jpg`:

![Here.jpg](flag/Here.jpg)

**Flag visible in the image:**

```
247CTF{850bb436XXXXXXXXXXXXXXXXc9b7b6c6}
```

---

## Complete Solution Script

```bash
#!/bin/bash

# 1. Extract MPTCP data from each subflow
for f in chall-i1.pcap chall-i2.pcap chall-i3.pcap; do
  tshark -r "$f" -T fields \
    -e tcp.options.mptcp.rawdataseqno \
    -e tcp.options.mptcp.datalvllen \
    -e tcp.payload 2>/dev/null \
    | grep -v "^$" > "${f%.pcap}_data.txt"
done

# 2. Combine by sorting by DSN
cat *_data.txt \
  | sort -t'	' -k1,1n \
  | cut -f3 \
  | tr -d ':' \
  | xxd -r -p > combined.bin

# 3. Extract ZIP (skip HTTP header)
dd if=combined.bin bs=1 skip=244 of=extracted.zip 2>/dev/null

# 4. Extract images
unzip -o extracted.zip "flag/Here.jpg"

echo "Flag is in flag/Here.jpg"
```

---

## Flag

```
247CTF{850bb436XXXXXXXXXXXXXXXXc9b7b6c6}
```

---

## MPTCP Flow Diagram

```
                    ┌─────────────────┐
                    │   Server        │
                    │   (Port 80)     │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
            ▼                ▼                ▼
    ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
    │  Subflow 1    │ │  Subflow 2    │ │  Subflow 3    │
    │  10.1.1.x     │ │  10.1.2.x     │ │  10.1.3.x     │
    │  4,835 pkts   │ │  14,940 pkts  │ │  10,287 pkts  │
    └───────────────┘ └───────────────┘ └───────────────┘
            │                │                │
            │    DSN orders the fragments     │
            └────────────────┼────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  HTTP Data      │
                    │  (ZIP 42 MB)    │
                    └─────────────────┘
```

---

## Challenge Takeaways

1. **MPTCP distributes data:** Fragments are sent through different paths but maintain global order via DSN
2. **DSN is the key:** The Data Sequence Number allows reconstruction of the original stream
3. **tshark extracts MPTCP:** The `tcp.options.mptcp.*` fields contain the necessary metadata
4. **Decoys in CTFs:** Files like `NOT_A_FLAG.jpg`, `NOT_FLAG.jpg`, etc. are distractions
