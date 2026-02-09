#!/usr/bin/env python3
import subprocess
import os

keys_file = "recovery_keys_dump.txt"
img_file = "encrypted_usb.dd"
mount_point = "/tmp/bitlocker_mount"

os.makedirs(mount_point, exist_ok=True)

with open(keys_file, 'r') as f:
    keys = [line.strip() for line in f if line.strip()]

print(f"Testing {len(keys)} keys...")

for i, key in enumerate(keys):
    if i % 100 == 0:
        print(f"Progress: {i}/{len(keys)}")
    
    # Try to decrypt
    result = subprocess.run(
        ["dislocker", "-V", img_file, f"-p{key}", "--", mount_point],
        capture_output=True,
        text=True,
        timeout=10
    )
    
    # Check if successful
    dislocker_file = os.path.join(mount_point, "dislocker-file")
    if os.path.exists(dislocker_file):
        print(f"\n*** SUCCESS! Key #{i+1}: {key}")
        print(f"Decrypted file at: {dislocker_file}")
        break
    
    # Cleanup
    subprocess.run(["fusermount", "-u", mount_point], capture_output=True)

print("Done!")
