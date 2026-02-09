#!/bin/bash
# Decrypt TLS traffic with recovered private key
# Usage: ./decrypt_tls.sh [pcap_file] [key_file]

PCAP="${1:-multiplication_tables.pcap}"
KEY="${2:-private_key.pem}"

if [ ! -f "$PCAP" ]; then
    echo "[-] PCAP not found: $PCAP"
    exit 1
fi

if [ ! -f "$KEY" ]; then
    echo "[-] Private key not found: $KEY"
    echo "[*] Run solve.py first to generate the key"
    exit 1
fi

echo "[*] Decrypting TLS traffic..."
echo "[*] PCAP: $PCAP"
echo "[*] Key:  $KEY"
echo ""
echo "========================================"

# Decrypt and show application data
ssldump -r "$PCAP" -k "$KEY" -d 2>&1 | while read line; do
    # Highlight flag if found
    if echo "$line" | grep -q "247CTF"; then
        echo -e "\033[1;32m$line\033[0m"
    elif echo "$line" | grep -q "application_data\|GET\|HTTP"; then
        echo "$line"
    fi
done

echo "========================================"
echo ""
echo "[*] For full output: ssldump -r $PCAP -k $KEY -d"
