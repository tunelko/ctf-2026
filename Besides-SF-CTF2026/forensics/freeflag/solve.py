#!/usr/bin/env python3
"""freeflag solver — recover deleted PNG from FAT16 free clusters"""
import struct

def main():
    with open("freeflag.bin", "rb") as f:
        data = f.read()

    # Parse FAT16 boot sector
    bps = struct.unpack_from('<H', data, 0x0B)[0]  # 512
    spc = data[0x0D]                                 # 4
    reserved = struct.unpack_from('<H', data, 0x0E)[0]  # 4
    num_fats = data[0x10]                             # 2
    root_entries = struct.unpack_from('<H', data, 0x11)[0]  # 512
    total_sectors = struct.unpack_from('<H', data, 0x13)[0]  # 32768
    spf = struct.unpack_from('<H', data, 0x16)[0]     # 32

    fat_start = reserved * bps
    fat_size = spf * bps
    root_dir_start = fat_start + num_fats * fat_size
    data_start = root_dir_start + root_entries * 32
    cluster_size = spc * bps
    total_clusters = (total_sectors * bps - data_start) // cluster_size

    # Read FAT1
    fat = data[fat_start:fat_start + fat_size]

    # Collect data from free (unallocated) clusters
    free_data = bytearray()
    for i in range(2, total_clusters + 2):
        entry = struct.unpack_from('<H', fat, i * 2)[0]
        if entry == 0x0000:  # Free
            offset = data_start + (i - 2) * cluster_size
            chunk = data[offset:offset + cluster_size]
            if any(b != 0 for b in chunk):
                free_data.extend(chunk)

    # Find PNG end (IEND chunk)
    iend_pos = free_data.find(b'IEND')
    if iend_pos == -1:
        print("No IEND found")
        return
    png_end = iend_pos + 8  # IEND + 4-byte CRC

    with open("free_image.png", "wb") as f:
        f.write(bytes(free_data[:png_end]))
    print(f"Recovered free_image.png ({png_end} bytes)")
    print(f"PNG header: {free_data[:8].hex() == '89504e470d0a1a0a'}")

if __name__ == "__main__":
    main()
