#!/usr/bin/env python3
"""
Challenge: 2025-Security-Report — upCTF 2026
Category:  forensics (PDF embedded file + password crack)
Flag:      upCTF{V3ry_b4d_S3cUriTy_P0stUr3}

Main PDF contains embedded appendix.pdf (encrypted RC4-128, password "Maki").
Extract embedded PDF → crack with hashcat → flag inside.
"""

import zlib
import subprocess
import sys

# Step 1: Extract embedded PDF from main report
with open("2025-Security-Report.pdf", "rb") as f:
    data = f.read()

idx = data.find(b"/Type /EmbeddedFile")
stream_start = data.find(b"stream\n", idx) + len(b"stream\n")
endstream = data.find(b"endstream", stream_start)
compressed = data[stream_start:endstream].rstrip()
decompressed = zlib.decompress(compressed)

with open("appendix.pdf", "wb") as f:
    f.write(decompressed)
print(f"[+] Extracted appendix.pdf ({len(decompressed)} bytes)")

# Step 2: Crack password with hashcat (mode 10500 = PDF 1.4-1.6 RC4-128)
# Hash: $pdf$2*3*128*-1028*1*16*09ceed129a1272db85e35a35b9a9afac*32*93c8eacdd09a9111dff6330391874fc800000000000000000000000000000000*32*b36a200c5d6b1caf700cad02dec3becede2c48dc59d30e272590886f73525d68
# Password: Maki (cracked in ~2 seconds with ?a?a?a?a mask)

# Step 3: Decrypt with known password
subprocess.run(["qpdf", "--password=Maki", "--decrypt", "appendix.pdf", "appendix_decrypted.pdf"], check=True)
print("[+] Decrypted appendix.pdf → appendix_decrypted.pdf")
print("[+] Flag: upCTF{V3ry_b4d_S3cUriTy_P0stUr3}")
