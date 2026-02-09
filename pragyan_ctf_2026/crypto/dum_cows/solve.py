#!/usr/bin/env python3
"""
dum-cows - Pragyan CTF 2026
Crypto Challenge - XOR Stream Cipher

Solution:
1. Extract keystream by sending known plaintext ('A' * 30)
2. Decrypt secret message by XORing empty-input encrypted message with keystream
3. Fix cow with: "FIX_COW <decrypted_secret>"
4. Decrypt Base64+XOR encrypted flag with full keystream

Flag: p_ctf{Giv3_sm-H20-t0_C0WSS:./}
"""

from pwn import *
import base64

context.log_level = 'info'

HOST = 'dum-cows.ctf.prgy.in'
PORT = 1337

def extract_keystream(length=30):
    """
    Extract keystream by sending known plaintext.

    The server XOR-encrypts our input with a keystream:
        encrypted_name = input XOR keystream

    Therefore:
        keystream = input XOR encrypted_name

    By sending 'A' * length, we extract the first 'length' bytes of keystream.

    NOTE: Server alternates between 2 keystream variants randomly.
    We extract both and try both for decryption.
    """
    log.info(f"Extracting keystream variants (trying {length} bytes)...")

    keystreams = {}

    # Try to get both variants (A and B)
    for _ in range(10):
        io = remote(HOST, PORT, ssl=True)
        io.recvuntil(b'name:')
        io.sendline(b'A' * length)
        response = io.recvall(timeout=2).decode()
        io.close()

        enc_name = response.split("[Name: ")[1].split("]")[0]
        name_bytes = base64.b64decode(enc_name)

        # XOR known plaintext 'A' (0x41) with encrypted bytes
        keystream = bytes([0x41 ^ b for b in name_bytes])

        # Identify variant by first byte
        variant_id = keystream[0]
        if variant_id not in keystreams:
            keystreams[variant_id] = keystream
            log.info(f"Variant {chr(65 + len(keystreams) - 1)} extracted: {keystream.hex()[:32]}...")

        if len(keystreams) >= 2:
            break

    return list(keystreams.values())


def decrypt_secret(keystreams):
    """
    Decrypt the secret message.

    When we send empty input:
    - Name is empty (no encryption)
    - Message is encrypted with: message XOR keystream[0:18]

    We XOR the encrypted message with the keystream to recover plaintext.
    Try both keystream variants.
    """
    log.info("Decrypting secret message...")

    io = remote(HOST, PORT, ssl=True)
    io.recvuntil(b'name:')
    io.sendline(b'')  # Empty input
    response = io.recvall(timeout=2).decode()
    io.close()

    enc_msg = response.split("says: ")[1].split("\n")[0]
    msg_bytes = base64.b64decode(enc_msg)

    # Try all keystream variants
    for keystream in keystreams:
        secret = bytes([m ^ k for m, k in zip(msg_bytes, keystream)])
        # Check if it's printable ASCII
        if all(32 <= b < 127 for b in secret):
            log.info(f"Secret decrypted: {secret.decode()}")
            return secret

    log.error("Failed to decrypt secret with any keystream!")
    return None


def fix_cow(secret):
    """
    Fix the broken cow and retrieve encrypted flag.

    The correct format is: "FIX_COW <secret>"
    This changes the cow from "DURRRRR!!!" to "Mooooo!!!" and reveals the flag.
    """
    log.info("Fixing the cow...")

    io = remote(HOST, PORT, ssl=True)
    io.recvuntil(b'name:')
    io.sendline(b'FIX_COW ' + secret)
    response = io.recvall(timeout=3).decode()
    io.close()

    if "Mooooo!!!" in response:
        log.info("Cow fixed, it says Mooooo")
    else:
        log.error("Cow still broken")
        print(response)
        return None

    # Extract encrypted flag
    enc_flag = response.split("FLAG SPEAKS:\n")[1].strip()
    log.info(f"Encrypted flag: {enc_flag}")

    return enc_flag


def decrypt_flag(enc_flag_b64, keystreams):
    """
    Decrypt the final flag.

    The flag is:
    1. XOR encrypted with the full keystream
    2. Base64 encoded

    We reverse: Base64 decode → XOR with keystream
    Try both keystream variants.
    """
    log.info("Decrypting flag...")

    flag_bytes = base64.b64decode(enc_flag_b64)

    # Try all keystream variants
    for keystream in keystreams:
        flag = bytes([f ^ keystream[i] for i, f in enumerate(flag_bytes)])
        # Check if it starts with known flag format
        if flag.startswith(b'p_ctf{') and flag.endswith(b'}'):
            return flag.decode()

    log.error("Failed to decrypt flag with any keystream!")
    return None


def main():
    """Main exploit flow"""
    log.info("dum-cows - Pragyan CTF 2026")
    log.info("XOR Stream Cipher Challenge")

    # Step 1: Extract keystream variants (30 bytes to cover flag length)
    keystreams = extract_keystream(30)
    log.info(f"Extracted {len(keystreams)} keystream variant(s)")

    # Step 2: Decrypt secret message
    secret = decrypt_secret(keystreams)
    if not secret:
        log.error("Failed to decrypt secret!")
        return

    # Step 3: Fix cow and get encrypted flag
    enc_flag = fix_cow(secret)
    if not enc_flag:
        log.error("Failed to fix cow!")
        return

    # Step 4: Decrypt flag
    flag = decrypt_flag(enc_flag, keystreams)
    if not flag:
        log.error("Failed to decrypt flag!")
        return

    log.info(f"\nFlag: {flag}")


if __name__ == "__main__":
    main()
