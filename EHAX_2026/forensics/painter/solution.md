# Painter - Forensics

**Category:** Forensics
**Author:** stapat
**Flag format:** EH4X{hihihihi}

## Flag

`EH4X{wh4t_c0l0ur_15_th3_fl4g}`

## Analysis

Challenge file: `pref.pcap` (pcapng, 1028572 bytes)

```
$ file pref.pcap
pref.pcap: pcapng capture file
```

USB HID mouse capture with 9888 frames. Each packet is 7 bytes (14 hex chars):

| Byte | Meaning |
|------|---------|
| 0 | Report ID (always 0x01) |
| 1 | Button state: 0x00=none, 0x01=left, 0x02=right |
| 2-3 | X displacement (signed 16-bit LE) |
| 4-5 | Y displacement (signed 16-bit LE) |
| 6 | Wheel (always 0x00) |

## Vulnerability / Trick

The painter drew text using **two mouse buttons** — left click (4274 packets) and right click (4109 packets). Rendering all points together produces an unreadable mess. Separating by button state reveals two lines of text that combine into the flag.

## Solution

1. Extract USB capdata:
```bash
tshark -r pref.pcap -T fields -e usb.capdata > mouse_data.txt
```

2. Parse packets, accumulate X/Y positions, separate by button state (byte 1)

3. Render each button's drawing separately:
   - **Right button (red, top line):** `wh4t_c0l0u`
   - **Left button (black, bottom line):** `r_15_th3_fl4g`

4. Combine: `wh4t_c0l0ur_15_th3_fl4g` = "what colour is the flag"

## Key Takeaways

- USB mouse captures encode relative displacements, not absolute positions — accumulate to reconstruct path
- Byte 0 can be a report ID (not button state) — verify by checking value distribution
- Multiple button states can encode separate layers of hidden data
- "Pen-up" (btn=0x00) events separate strokes but characters may be drawn in one continuous stroke per button
