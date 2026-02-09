#!/bin/bash
# Data Extraction Script for Webshell Challenge
# Run after unzipping web_shell.pcap

PCAP="web_shell.pcap"

echo "[*] Extracting HTTP responses from webshell..."

# Extract all responses from owned.php
for stream in $(seq 160 284); do
    tshark -r "$PCAP" -q -z "follow,tcp,ascii,$stream" 2>/dev/null \
        | grep -o "kkqES1eCIzoxyHXb775d4f83f4e0[A-Za-z0-9+/=]*0120dd0bccc6"
done > all_responses.txt

echo "    Responses saved to all_responses.txt ($(wc -l < all_responses.txt) lines)"

echo "[*] Extracting POST commands..."

tshark -r "$PCAP" \
    -Y "http.request.method == POST and http.request.uri contains owned.php" \
    -T fields -e http.file_data 2>/dev/null > all_commands.txt

echo "    Commands saved to all_commands.txt ($(wc -l < all_commands.txt) lines)"

echo "[*] Running decoder..."
python3 decode_webshell.py all_commands.txt all_responses.txt
