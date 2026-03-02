#!/bin/bash
# TheGrue2 - Flag Extraction Script
# HackOn CTF - Misc Category

echo "[*] TheGrue2 - Unity Game Flag Extractor"
echo "[*] ======================================="
echo ""

GAME_DIR="TheGrue 3D GamePwn IL2CPP/ctf-thegrue_Data"

if [ ! -d "$GAME_DIR" ]; then
    echo "[-] Game directory not found: $GAME_DIR"
    exit 1
fi

echo "[*] Analyzing Unity level files..."
echo ""

cd "$GAME_DIR"

# Search all level files
for level in level0 level1 level2; do
    if [ -f "$level" ]; then
        echo "[*] Checking $level..."
        result=$(strings "$level" | grep -i "HackOn{")
        if [ -n "$result" ]; then
            echo "[+] FLAG FOUND in $level!"
            echo ""
            echo "=== Context ==="
            strings "$level" | grep -B3 -A1 "HackOn{"
            echo ""
            echo "=== FLAG ==="
            echo "$result"
            exit 0
        fi
    fi
done

echo "[-] No flag found in level files"
exit 1
