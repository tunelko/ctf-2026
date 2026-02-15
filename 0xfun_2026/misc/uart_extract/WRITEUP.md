# UART — Misc (50 pts)

**CTF:** 0xFun CTF 2026
**Category:** Misc
**Difficulty:** Beginner
**Author:** x03e
**Flag:** `0xfun{UART_82_M2_B392n9dn2}`

---

## Description

> A strange transmission has been recorded. Something valuable lies within.

Provided file: `uart.sr`

## Analysis

The `.sr` file is a Sigrok/PulseView capture (logic analyzer). It is a ZIP containing:

```
version    -> "2"
metadata   -> sample rate, channels, etc.
logic-1-1  -> binary signal data
```

### Metadata

```
sigrok version=0.6.0-git-f06f788
capturefile=logic-1
total probes=1
samplerate=1 MHz
probe1=uart.ch1
unitsize=1
```

- **1 channel** UART
- **1 MHz** sample rate (1 us per sample)
- **2400 samples** = 2.4 ms capture
- Each byte in the file = one sample (0x00=LOW, 0x01=HIGH)

### Baud rate determination

Analyzing the distances between signal transitions:

| Distance (samples) | Frequency |
|---|---|
| 9 | 65 |
| 17 | 38 |
| 8 | 37 |

The minimum distance is **8 samples**, corresponding to a baud rate of `1,000,000 / 8 = 125,000 baud`. This also matches a rate close to 115200 baud (8.68 samples/bit), a standard UART value.

## Decoding

Standard UART protocol **8N1** (8 data bits, no parity, 1 stop bit):

1. **Idle**: line at HIGH
2. **Start bit**: transition to LOW (1 bit)
3. **Data bits**: 8 bits, LSB first
4. **Stop bit**: HIGH (1 bit)

```python
#!/usr/bin/env python3
import zipfile

with zipfile.ZipFile('uart.sr', 'r') as z:
    data = z.read('logic-1-1')

bits = list(data)
bit_period = 8.0  # 125000 baud

decoded = []
i = 0
while i < len(bits):
    if bits[i] == 1:  # idle
        i += 1
        continue

    start = i
    # Verify start bit at center
    if bits[int(start + bit_period / 2)] != 0:
        i += 1
        continue

    # Read 8 data bits (LSB first)
    byte_val = 0
    for bit_idx in range(8):
        pos = int(start + bit_period * (1.5 + bit_idx))
        if pos >= len(bits):
            break
        byte_val |= (bits[pos] << bit_idx)

    decoded.append(byte_val)
    i = int(start + bit_period * 10)  # start + 8 data + 1 stop + margin

print(bytes(decoded).decode())
# -> 0xfun{UART_82_M2_B392n9dn2}
```

## Result

```
0xfun{UART_82_M2_B392n9dn2}
```
