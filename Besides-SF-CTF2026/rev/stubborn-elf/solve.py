#!/usr/bin/env python3
"""stubborn-elf solver — XOR-decode flag after deadbeefcafebabe marker"""

def main():
    with open("stubborn", "rb") as f:
        data = f.read()

    marker = bytes.fromhex("deadbeefcafebabe")
    pos = data.find(marker)
    if pos == -1:
        print("Marker not found")
        return

    encoded = data[pos + len(marker):]
    # XOR key derived from known prefix: 0x01 XOR 'C' = 0x42
    key = 0x42
    flag = bytes(b ^ key for b in encoded).decode('ascii', errors='replace')
    print(f"Flag: {flag}")

if __name__ == "__main__":
    main()
