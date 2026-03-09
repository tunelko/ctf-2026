# Good Vibes

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | diceCTF 2026                   |
| Category    | misc (network/crypto)          |
| Difficulty  | Medium                         |

## Description
> operating on good vibes has no real consequences... surely...

## TL;DR
Custom VPN ("vibepn") derives its AES-256-GCM session key from `time(NULL)` via a weak LCG PRNG. Brute-force the seed from PCAP timestamps, decrypt the tunnel traffic, find the flag encoded as a raw ASCII "IPv6 packet".

## Initial Analysis

### Challenge Contents

```bash
$ tar xzf misc_good-vibes.tar.gz
$ file challenge.pcap
challenge.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Linux cooked v2, capture length 262144)
```

Single PCAP file. Also provided separately: `vibepn-client` ELF binary (the VPN client).

### PCAP overview

```bash
$ tshark -r challenge.pcap -q -z io,phs
Protocol Hierarchy Statistics
sll
  ip
    tcp                                  frames:242 bytes:17211
      data                               frames:39 bytes:4079
    icmp                                 frames:43 bytes:5268
    udp                                  frames:2039 bytes:2790713
      data                               frames:2039 bytes:2790713
  ipv6
    icmpv6                               frames:12 bytes:864
    udp
      ntp                                frames:2 bytes:232
```

Bulk of the traffic is UDP data. 2338 packets over ~309 seconds.

### TCP conversation on port 6767

```bash
$ tshark -r challenge.pcap -Y "tcp.port == 6767" -T fields -e tcp.payload | tr -d '\n' | xxd -r -p
```

Plaintext IRC-style chat between two parties:

```
hi
hi
did anyone tell you you're an idiot
what
did you not get the memo
use the damn vpn#
what's a vpn
how do you not
what
ok
what
how are you so stupid
whatever
i coded it myself so its super secure
i'm sure it is
i dont want your sarcasm
you got one of us killed before, i dont want another incident.
just like
https://gofile.io/d/l6XqnD
you know the rest
is this malware??
what the
i give up with you
only speak to me over the vpn from now on
```

Key takeaways:
- They switch to a custom VPN after this conversation
- VPN client shared via gofile link (expired, but binary provided separately)
- "i coded it myself so its super secure" — custom crypto, likely weak

### UDP traffic analysis

```bash
$ tshark -r challenge.pcap -Y "udp" -T fields -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e udp.length | sort | uniq -c | sort -rn | head -5
973 95.216.195.5    167.235.254.47  43448  5959  1420
973 10.7.0.2        10.7.0.1        53582  5201  1356
 10 95.216.195.5    167.235.254.47  43448  5959  88
  9 167.235.254.47  95.216.195.5    5959   43448 88
```

Two main UDP flows:
1. **Port 5959**: VPN traffic between `95.216.195.5` and `167.235.254.47` (1033 packets)
2. **Port 5201**: iperf3 benchmark traffic (noise, irrelevant)

## Reversing the VPN client

```bash
$ file vibepn-client
vibepn-client: ELF 64-bit LSB pie executable, x86-64, not stripped

$ strings -n 8 vibepn-client | head -10
EVP_EncryptUpdate
EVP_PKEY_CTX_free
...
EVP_aes_256_gcm
libcrypto.so.3
```

Not stripped, links against OpenSSL `libcrypto.so.3`. Uses ECDH + AES-256-GCM.

### Key functions (radare2)

```bash
$ r2 -q -e scr.color=0 -c 'aaa; afl' vibepn-client
```

| Function | Purpose |
|----------|---------|
| `vpn_generate_keypair` | EC P-256 keypair generation |
| `vpn_derive_session_key` | **Derives 32-byte AES key from `time(NULL)` via LCG** |
| `vpn_encrypt` | AES-256-GCM encrypt with 12-byte nonce, 20-byte AAD |
| `vpn_decrypt` | AES-256-GCM decrypt |
| `start_handshake` | ECDH handshake (type 0x01-0x04 packets) |
| `send_packet.isra.0` | Wire format: `BE TYPE LEN[2] SEQ[4] NONCE[12] CT TAG[16]` |

### The vulnerability: `vpn_derive_session_key`

```bash
$ r2 -q -e scr.color=0 -c 'aaa; s sym.vpn_derive_session_key; pdf' vibepn-client
```

Disassembly (simplified pseudocode):

```c
void vpn_derive_session_key(char *key_buf) {
    uint32_t seed = (uint32_t)time(NULL);
    for (int i = 0; i < 32; i++) {
        seed = seed * 0x19660d + 0x3c6ef35f;  // LCG
        key_buf[i] = (uint8_t)(seed & 0xFF);
    }
}
```

The AES-256-GCM session key is derived entirely from `time(NULL)` using a textbook LCG (Linear Congruential Generator). The seed is a 32-bit Unix timestamp — trivially brute-forceable given the PCAP's capture timestamps.

### Wire format

```
Offset  Size  Field
0       1     Magic (0xBE)
1       1     Type (0x01=HELLO, 0x02=HELLO_RESP, 0x03=CHALLENGE, 0x04=ACK, 0x10=DATA, 0x20=KEEPALIVE)
2       2     Payload length (big-endian)
4       4     Sequence number (big-endian)
8       12    Nonce (GCM IV)
20      var   Ciphertext
-16     16    GCM authentication tag
```

The full 20-byte header is used as AAD (Additional Authenticated Data) for GCM.

## Solution Process

### Step 1: Extract VPN packets

```bash
$ tshark -r challenge.pcap -Y "udp.port == 5959" -T fields -e ip.src -e data.data -e frame.time_epoch > vpn_packets.txt
```

1033 VPN packets. First data packet at epoch `1772156047`.

### Step 2: Brute-force the LCG seed

The key derivation uses `time(NULL)` as seed. We don't know the exact server time, but it must be within a few hours of the PCAP timestamps.

```python
def derive_key(seed):
    key = bytearray(32)
    val = seed & 0xFFFFFFFF
    for i in range(32):
        val = (val * 0x19660d + 0x3c6ef35f) & 0xFFFFFFFF
        key[i] = val & 0xFF
    return bytes(key)
```

Brute-force +/- 2 hours from the first data packet timestamp:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

base_time = 1772156047  # first data packet epoch
for delta in range(-7200, 7200):
    seed = base_time + delta
    key = derive_key(seed)
    try:
        aesgcm = AESGCM(key)
        aesgcm.decrypt(nonce, ct_tag, header_aad)
        print(f"Found seed: {seed}")
        break
    except Exception:
        pass
```

```
[+] Found seed: 1772148879 (delta=-7168s from PCAP time)
    Session key: a2992433f6dd98178a614c3b5e25409f72297443c66de8275af19c4b2eb590af
```

### Step 3: Decrypt all VPN traffic

With the key, decrypt all 1029 data/keepalive packets (types 0x10 and 0x20).

Inner traffic is IPv6 — mostly link-local router solicitations (`fe80::` -> `ff02::2`).

### Step 4: Find the flag in decrypted traffic

One set of repeated packets has non-link-local IPv6 addresses that decode as ASCII:

```
Src: 5f73:6830:756c:645f:616c:7740:7973:5f76  ->  "_sh0uld_alw@ys_v"
Dst: 6962:335f:7930:7572:5f76:706e:735f:3832  ->  "ib3_y0ur_vpns_82"
```

But the entire "IPv6 packet" is actually raw ASCII — including the version/TC/flow/plen/nh/hlim header fields:

```
Bytes 0-7:  64 69 63 65 7b 79 30 75  ->  "dice{y0u"
Bytes 8-23: (src addr)               ->  "_sh0uld_alw@ys_v"
Bytes 24-39: (dst addr)              ->  "ib3_y0ur_vpns_82"
Bytes 40-43: 62 63 33 7d             ->  "bc3}"
```

The flag is the packet itself interpreted as ASCII:

```
dice{y0u_sh0uld_alw@ys_vib3_y0ur_vpns_82bc3}
```

## Execution

```bash
python3 solve.py
```

```
[*] Extracting VPN packets from PCAP...
    Total VPN packets: 1033
    First data packet epoch: 1772156047
[*] Brute-forcing LCG seed (time-based, +/- 2 hours)...
[+] Found seed: 1772148879 (delta=-7168s from PCAP time)
    Session key: a2992433f6dd98178a614c3b5e25409f72297443c66de8275af19c4b2eb590af
[*] Decrypting VPN traffic...
    Decrypted 1029 packets

[+] Flag: dice{y0u_sh0uld_alw@ys_vib3_y0ur_vpns_82bc3}
```

## Flag
```
dice{y0u_sh0uld_alw@ys_vib3_y0ur_vpns_82bc3}
```

## Key Lessons
- `time(NULL)` as a PRNG seed gives ~32 bits of entropy at best — trivially brute-forceable in seconds
- Even AES-256-GCM is worthless if the key derivation is weak ("i coded it myself so its super secure")
- The ECDH handshake was a red herring — the session key ignores it entirely and uses the LCG instead
- Flag was hidden as raw ASCII bytes masquerading as an IPv6 packet inside the VPN tunnel
- The plaintext TCP conversation provided critical context: custom VPN, gofile link to client binary
