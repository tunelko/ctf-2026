#!/bin/bash
# orphan: Extract orphaned inode 13 from ext2 image
xz -dk orphan.xz 2>/dev/null
echo "dump <13> flag.png" | debugfs orphan 2>/dev/null
echo "[+] Dumped inode 13 → flag.png"
echo "[+] Open flag.png to read: CTF{please_sir_can_i_have_a_flag}"
