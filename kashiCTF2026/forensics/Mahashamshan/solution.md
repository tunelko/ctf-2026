# Mahashamshan

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | KashiCTF 2026                  |
| Categoría   | forensics                      |
| Puntos      | 475                            |

## Descripcion
> A packet capture was pulled from a compromised node inside a covert communications network.
> "The river does not reveal itself. It only flows."
> "Not all fields are what they seem. The fragment offset field hides more than offset."

## TL;DR
Covert channel in crafted IP fragments. Flag encoded in low bytes of IP ID field (XOR 0x21), ordered by TCP sequence numbers embedded in fragment payloads.

## Proceso

### Paso 1: Identify the covert channel
```bash
tshark -r mahashamshan_2.pcap -c 20
```

PCAP contains ~216 packets: mostly noise (random TCP SYN/ACK, ARP with `de:ad:be:ef:13:37` MAC, ICMP pings to 1.1.1.1). The interesting packets are 41 fragmented IP packets from `192.168.7.77 → 10.13.37.1` (leet address).

All fragmented packets share:
- Fragment offset = 5 (40 bytes), flags = DF set (contradictory — DF + fragment = crafted)
- Same HTTP POST payload: `POST /api/v1/sync HTTP/1.1\r\nHost: internal.svc\r\n...`
- Varying IP ID and TCP source port / sequence number

### Paso 2: Extract and order the packets
The TCP sequence numbers in the fragment payloads form a linear progression (0, 123456, 246912, ...). This provides the ordering.

```python
from scapy.all import rdpcap, IP
pkts = rdpcap("mahashamshan_2.pcap")

frags = []
for i, p in enumerate(pkts):
    if IP in p and p[IP].src == "192.168.7.77" and p[IP].dst == "10.13.37.1":
        ip = p[IP]
        payload = bytes(ip.payload)
        tcp_seq = int.from_bytes(payload[4:8], 'big')
        frags.append((ip.id, tcp_seq))

frags.sort(key=lambda x: x[1])  # sort by TCP seq
```

### Paso 3: Decode the IP ID field
When sorted by TCP seq, the IP ID high bytes form a perfect descending counter (0x62 → 0x3a). The LOW byte of each IP ID carries the encoded data.

```python
low_bytes = [ipid & 0xff for ipid, _ in frags]
# XOR with 0x21
flag = ''.join(chr(b ^ 0x21) for b in low_bytes)
# kashiCTF{fr4g_b1t5_4r3_my_5ecr3t_c4rr13r}
```

The XOR key 0x21 was identified by testing: `0x4a ^ 0x21 = 0x6b = 'k'`, `0x40 ^ 0x21 = 0x61 = 'a'`, ... spelling "kashiCTF{".

### Ragebaits / Red Herrings
- ARP packets from `de:ad:be:ef:13:37` — noise
- TCP URG packets to 172.31.0.1:8443 — noise  
- ICMP pings with id=0x4141 — noise
- DNS queries to 8.8.8.8 — noise
- The HTTP POST payload in fragments — same in all packets, decoy
- The hint about "fragment offset field" — the real data is in the IP ID field, not fragment offset

## Flag
```
kashiCTF{fr4g_b1t5_4r3_my_5ecr3t_c4rr13r}
```

## Key Lessons
- In IP covert channels, ANY header field can carry data — IP ID is a classic choice
- When multiple packets carry fragments of a message, look for an ordering mechanism (here: TCP seq in payload)
- High byte as counter + low byte as data is a common IP ID steganography pattern
- Single-byte XOR is easily broken by testing against known flag prefix
- "Fragment offset" hint was misdirection — always verify by examining the actual data
