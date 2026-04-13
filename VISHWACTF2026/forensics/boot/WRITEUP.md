# BOOT

**CTF**: VishwaCTF 2026
**Category**: Forensics
**Flag**: `VishwaCTF{iM4G35_4Re_n0t_th4T_c00L}`

## TL;DR

Bootable TinyCore Linux ISO with a base58-encoded flag appended to the `isolinux.bin` boot loader file.

## Analysis

The challenge provides a 25MB bootable ISO image (TinyCore Linux 17.0). The title hint "or not to BOOT" suggests looking at the boot-related files rather than the OS itself.

### Step 1: Mount and explore

```bash
mount -o loop boot.iso /tmp/boot_iso
find /tmp/boot_iso -type f
```

Standard TinyCore Plus structure: vmlinuz, core.gz initrd, isolinux bootloader, TCZ extensions.

### Step 2: Check file timestamps

The ISO was created on 2026-03-10. Most files have their original TinyCore timestamps, but `isolinux.bin` was modified on the same day as the ISO creation:

```
2026-03-10 15:01:24  boot/isolinux/isolinux.bin  (24723 bytes)
```

A standard isolinux 4.05 binary is ~24576 bytes. This one is **147 bytes larger**.

### Step 3: Examine the extra data

```bash
tail -c 200 /tmp/boot_iso/boot/isolinux/isolinux.bin | xxd
```

The last ~150 bytes contain a repeated string:
```
9d5zYNcj9f1S46vC74aruPgE9b6T3ceX4Qsa2VQAbVnDFfTr
```

### Step 4: Decode

The string is **base58** encoded:

```python
import base58
base58.b58decode("9d5zYNcj9f1S46vC74aruPgE9b6T3ceX4Qsa2VQAbVnDFfTr")
# b'VishwaCTF{iM4G35_4Re_n0t_th4T_c00L}'
```

## Key Takeaways

- Always check file sizes against known-good versions — 147 extra bytes in a standard binary is suspicious
- The boot loader is an unusual but effective hiding spot — most forensic tools focus on the filesystem, not the bootloader binary
- Base58 encoding (no +, /, 0, O, I, l characters) is common in crypto/CTF contexts

## Files

- `boot.iso` — Challenge ISO image
- `boot_flag.txt` — Captured flag
