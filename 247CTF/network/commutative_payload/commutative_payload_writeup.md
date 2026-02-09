# Commutative Payload - Honeypot Attack Analysis

## Challenge Description
We have a honeypot running on one of our internal networks. We received an alert today that the machine was compromised, but we can't figure out what the attacker did. Can you find the flag hidden in the attacker's payload?

## Analysis

### Traffic Overview
```bash
tshark -r commutative_payload.pcap -q -z conv,tcp
```

The pcap shows SMB traffic (port 445) from attacker 10.0.5.15 to victim 192.168.10.168, typical of an SMB exploit like EternalBlue.

### The Hint: "Commutative"
The filename `commutative_payload.pcap` is a strong hint. **XOR** is a commutative operation:
- `a XOR b = b XOR a`
- `(a XOR key) XOR key = a`

This suggests the payload is XOR-encoded.

### Payload Extraction
Extract all TCP payloads:
```bash
tshark -r commutative_payload.pcap -T fields -e tcp.payload | tr -d '\n' | xxd -r -p > all_payloads.bin
```

### XOR Brute Force
```python
data = open('all_payloads.bin', 'rb').read()
target = b'247CTF'

for key in range(256):
    decoded = bytes([b ^ key for b in data])
    if target in decoded:
        pos = decoded.find(target)
        print(f"Key 0x{key:02x}: Found at position {pos}")
        print(decoded[pos:pos+50])
        break
```

### Result
```
Key 0x14: Found at position 75205
b'247CTF{7b3626cdXXXXXXXXXXXXXXXX7356f229}\x00FLAG\x00'
```

## Flag
```
247CTF{7b3626cdXXXXXXXXXXXXXXXX7356f229}
```

## Aprendizaje del reto

1. **Commutative Operations**: XOR is commutative and self-inverse, making it common for simple payload obfuscation
2. **SMB Exploitation**: Traffic pattern shows typical SMB-based attack (EternalBlue-style)
3. **Single-byte XOR**: Simple but effective obfuscation; easily broken with known plaintext ("247CTF")

## Tools Used
- `tshark` - Packet analysis and payload extraction
- Python - XOR brute force decryption
