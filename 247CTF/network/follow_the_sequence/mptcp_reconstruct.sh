#!/bin/bash
# MPTCP Subflow Reconstruction Script
# For 247CTF "Follow The Sequence" Challenge

echo "[*] Extracting MPTCP data from all subflows..."

# Extract DSN, length, and payload from each pcap
for f in chall-i1.pcap chall-i2.pcap chall-i3.pcap; do
    echo "    Processing $f..."
    tshark -r "$f" -T fields \
        -e tcp.options.mptcp.rawdataseqno \
        -e tcp.options.mptcp.datalvllen \
        -e tcp.payload 2>/dev/null \
        | grep -v "^$" > "${f%.pcap}_data.txt"
done

echo "[*] Combining and sorting by DSN..."

# Combine all data, sort by DSN (first column), extract payload
cat chall-i1_data.txt chall-i2_data.txt chall-i3_data.txt \
    | sort -t'	' -k1,1n \
    | cut -f3 \
    | tr -d ':' \
    | xxd -r -p > combined.bin

echo "[*] Combined file size: $(wc -c < combined.bin) bytes"
echo "[*] File type: $(file combined.bin)"

# Check for HTTP header and extract ZIP
if head -c 20 combined.bin | grep -q "HTTP"; then
    echo "[*] Found HTTP response, extracting ZIP..."
    # Find PK signature offset
    OFFSET=$(grep -boa "PK" combined.bin | head -1 | cut -d: -f1)
    if [ -n "$OFFSET" ]; then
        dd if=combined.bin bs=1 skip=$OFFSET of=extracted.zip 2>/dev/null
        echo "[*] ZIP extracted to extracted.zip"
        echo "[*] ZIP contents:"
        unzip -l extracted.zip
    fi
fi

echo "[*] Done!"
