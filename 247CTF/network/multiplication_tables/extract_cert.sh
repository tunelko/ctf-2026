#!/bin/bash
# Extract certificate and RSA parameters from TLS pcap
# Usage: ./extract_cert.sh [pcap_file]

PCAP="${1:-multiplication_tables.pcap}"

if [ ! -f "$PCAP" ]; then
    echo "[-] File not found: $PCAP"
    exit 1
fi

echo "[*] Extracting certificate from $PCAP..."
echo ""

# Extract certificate as DER
tshark -r "$PCAP" -Y "tls.handshake.certificate" \
    -T fields -e tls.handshake.certificate 2>/dev/null \
    | head -1 | xxd -r -p > cert.der

if [ ! -s cert.der ]; then
    echo "[-] No certificate found in pcap"
    exit 1
fi

echo "[*] Certificate saved to cert.der ($(wc -c < cert.der) bytes)"
echo ""

echo "[*] Certificate details:"
echo "========================================"
openssl x509 -inform der -in cert.der -text -noout 2>/dev/null | head -25
echo "========================================"
echo ""

echo "[*] RSA Modulus (hex):"
MODULUS=$(openssl x509 -inform der -in cert.der -noout -modulus 2>/dev/null | cut -d= -f2)
echo "$MODULUS"
echo ""

# Convert to decimal for FactorDB
echo "[*] RSA Modulus (decimal):"
python3 -c "print(int('$MODULUS', 16))"
echo ""

echo "[*] To factor N, query FactorDB:"
echo "    http://factordb.com/?query=$(python3 -c "print(int('$MODULUS', 16))")"
