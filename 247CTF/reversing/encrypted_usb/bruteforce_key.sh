#!/bin/bash
cd /root/ctf/reversing_432
IMG="encrypted_usb.dd"
KEYS="recovery_keys_dump.txt"

mkdir -p decrypted

count=0
total=$(wc -l < "$KEYS")

while IFS= read -r key; do
    count=$((count + 1))
    if [ $((count % 50)) -eq 0 ]; then
        echo "Progress: $count / $total"
    fi
    
    # Try to decrypt with this key
    result=$(dislocker-fuse -V "$IMG" -p"$key" -- decrypted 2>&1)
    
    if [ $? -eq 0 ] && [ -f decrypted/dislocker-file ]; then
        echo "SUCCESS! Key found at line $count: $key"
        ls -la decrypted/
        exit 0
    fi
    
    # Cleanup
    fusermount -u decrypted 2>/dev/null
done < "$KEYS"

echo "No valid key found!"
