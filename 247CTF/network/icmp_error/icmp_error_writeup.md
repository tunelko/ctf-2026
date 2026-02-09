# ICMP Error Reporting - Writeup

## Challenge Description
Can you identify the flag hidden within the error messages of this ICMP traffic?

## Analysis

### Initial Inspection
The challenge provides a pcap file `error_reporting.pcap` containing ICMP traffic.

```bash
tshark -r error_reporting.pcap -Y "icmp" -T fields -e icmp.type -e icmp.code -e data | head -5
```

### Traffic Breakdown
- **ICMP Type 8 (Echo Request)**: Contains hex `53656e642074686520666c616721` which decodes to "Send the flag!"
- **ICMP Type 0 (Echo Reply)**: Multiple packets containing binary data starting with `ffd8ffe0` - the JPEG magic bytes

### Data Exfiltration via ICMP
The flag is hidden inside a JPEG image that was split across multiple ICMP echo reply packets. This is a common data exfiltration technique where data is embedded in ICMP payload fields.

## Solution

### Extract JPEG from ICMP Replies
```bash
tshark -r error_reporting.pcap -Y "icmp.type == 0" -T fields -e data | tr -d '\n' | xxd -r -p > flag.jpg
```

### Verify the Image
```bash
file flag.jpg
# JPEG image data, JFIF standard 1.01, progressive, 500x500
```

### View the Image
The extracted JPEG shows the "Hackerman" meme with the flag embedded at the bottom.

## Flag
```
247CTF{580e6d62XXXXXXXXXXXXXXXXd6284ddf}
```

## Lessons Learned

1. **ICMP Data Exfiltration**: ICMP packets can carry arbitrary data in their payload, making them useful for covert data transfer
2. **JPEG Magic Bytes**: `FF D8 FF E0` identifies JPEG/JFIF files
3. **Packet Reassembly**: Data split across multiple packets needs to be concatenated in order

## Tools Used
- `tshark` - Command-line packet analyzer
- `xxd` - Hex dump/reverse tool
