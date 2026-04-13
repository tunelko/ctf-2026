# Hidden_Network - VishwaCTF 2026 (Forensics)

## Flag
`VishwaCTF{H1DDN3TWRKK}`

## TL;DR
PCAP contains an HTTP GET for `report.txt`. The response body has Unicode zero-width steganography: U+200B (zero-width space) = 0, U+200C (zero-width non-joiner) = 1. Extract the bits, convert to ASCII.

## Analysis
- 9-packet PCAP: TCP handshake + HTTP GET `/report.txt` + response
- Response is a fake "Network Diagnostics Report" with hint: *"the most interesting data is often the data you cannot see"*
- Between every visible character, zero-width Unicode characters are embedded:
  - `\xe2\x80\x8b` (U+200B) → bit 0
  - `\xe2\x80\x8c` (U+200C) → bit 1
- 176 bits → 22 ASCII characters → flag

## Solve
```python
with open('report.txt', 'rb') as f:
    data = f.read()
bits = ''
i = 0
while i < len(data) - 2:
    if data[i:i+3] == b'\xe2\x80\x8b': bits += '0'; i += 3
    elif data[i:i+3] == b'\xe2\x80\x8c': bits += '1'; i += 3
    else: i += 1
flag = ''.join(chr(int(bits[j:j+8], 2)) for j in range(0, len(bits)-7, 8))
print(flag)
```
