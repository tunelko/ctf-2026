#!/usr/bin/env python3
"""
BEAST Attack on AES-CBC with Predictable IV
Based on: https://medium.com/@giritharram005/247ctf-cryptography-part-3-5797e270eed8
"""

import requests
import binascii

URL = "https://9cd2896dc2f9cedf.247ctf.com/"

# Possible flag characters (hex: 0-9, a-f)
possibilities = ['30','31','32','33','34','35','36','37','38','39','61','62','63','64','65','66']
texts = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P']

def get_IV(session, converted_text):
    """Encrypt and return the IV (last 32 hex chars = 16 bytes)"""
    result = session.get(URL + 'encrypt?plaintext=' + converted_text)
    return result.text[-32:]

def xor_operation(a, b):
    """XOR two strings and return hex"""
    xored = []
    for i in range(len(a)):
        xored_value = ord(a[i % len(a)]) ^ ord(b[i % len(b)])
        hex_value = hex(xored_value)[2:]
        if len(hex_value) == 1:
            hex_value = "0" + hex_value
        xored.append(hex_value)
    return ''.join(xored)

def method1_first_16_bytes():
    """Recover first 16 bytes of flag using BEAST attack"""
    print("=== Method 1: Recovering first 16 bytes ===\n")

    session = requests.Session()
    retrieved_flag = ''
    retrieved_flag_chr = ''
    count = 31

    for i in range(16):
        print(f"Byte {i}: ", end="", flush=True)
        found = False

        for possible_value, text in zip(possibilities, texts):
            # Padding text
            converted_text = binascii.hexlify(bytes(text, 'utf-8') * count).decode('utf-8')
            known_text = text * count

            # Get IV from dummy request
            IV = get_IV(session, converted_text)

            # First request: XOR block 1 with IV to nullify
            IV_bytes = bytes.fromhex(IV).decode('latin-1')
            xored_value1 = xor_operation(IV_bytes, known_text[:16])

            result1 = session.get(URL + 'encrypt?plaintext=' + xored_value1 + converted_text[32:])

            if "predictable" in result1.text.lower():
                # Need new session
                session = requests.Session()
                continue

            # Second request: same XOR but with guess appended
            IV2 = bytes.fromhex(result1.text[-32:]).decode('latin-1')
            xored_value2 = xor_operation(IV2, known_text[:16])

            result2 = session.get(URL + 'encrypt?plaintext=' + xored_value2 + converted_text[32:] + retrieved_flag + possible_value)

            if "predictable" in result2.text.lower():
                session = requests.Session()
                continue

            # Compare C2 blocks (bytes 32-64 in hex = block index 1)
            if result1.text[32:64] == result2.text[32:64]:
                retrieved_flag += possible_value
                ascii_char = binascii.unhexlify(possible_value).decode('ascii')
                retrieved_flag_chr += ascii_char
                print(f"'{ascii_char}' -> {retrieved_flag_chr}")
                count -= 1
                found = True
                break

        if not found:
            print("FAILED - trying new session")
            session = requests.Session()
            # Retry this byte
            continue

    return retrieved_flag, retrieved_flag_chr

def method2_last_16_bytes(retrieved_flag, retrieved_flag_chr):
    """Recover last 16 bytes using the known first 16 bytes"""
    print("\n=== Method 2: Recovering last 16 bytes ===\n")

    session = requests.Session()
    count = 31 - len(retrieved_flag) // 2

    for i in range(16):
        print(f"Byte {16 + i}: ", end="", flush=True)
        iteration_count = i + 1
        found = False

        for possible_value, text in zip(possibilities, texts):
            converted_text = binascii.hexlify(bytes(text, 'utf-8') * count).decode('utf-8')
            known_text = text * count

            # Get IV
            IV = get_IV(session, converted_text)

            # First request
            result1 = session.get(URL + 'encrypt?plaintext=' + converted_text)

            if "predictable" in result1.text.lower():
                session = requests.Session()
                continue

            # XOR IVs together, then with known text + known flag prefix
            IV_bytes = bytes.fromhex(IV).decode('latin-1')
            IV2_bytes = bytes.fromhex(result1.text[-32:]).decode('latin-1')
            xored_value1 = bytes.fromhex(xor_operation(IV_bytes, IV2_bytes)).decode('latin-1')
            xored_value2 = xor_operation(xored_value1, known_text + retrieved_flag_chr[:iteration_count])

            # Second request with guess
            result2 = session.get(URL + 'encrypt?plaintext=' + xored_value2 + retrieved_flag[iteration_count*2:] + possible_value)

            if "predictable" in result2.text.lower():
                session = requests.Session()
                continue

            # Compare C2 blocks
            if result1.text[32:64] == result2.text[32:64]:
                ascii_char = binascii.unhexlify(possible_value).decode('ascii')
                retrieved_flag_chr += ascii_char
                retrieved_flag += possible_value
                print(f"'{ascii_char}' -> {retrieved_flag_chr}")
                count -= 1
                found = True
                break

        if not found:
            print("FAILED - trying new session")
            session = requests.Session()

    return retrieved_flag, retrieved_flag_chr

def main():
    print("=== BEAST Attack on Predictable IV ===\n")

    # Method 1: Get first 16 bytes
    flag_hex, flag_chr = method1_first_16_bytes()
    print(f"\nFirst 16 bytes: {flag_chr}")

    if len(flag_hex) == 32:  # 16 bytes = 32 hex chars
        # Method 2: Get last 16 bytes
        flag_hex, flag_chr = method2_last_16_bytes(flag_hex, flag_chr)

    print(f"\n{'='*50}")
    print(f"Flag (hex): {flag_hex}")
    print(f"Flag (ascii): {flag_chr}")
    print(f"Submit: 247CTF{{{flag_chr}}}")

if __name__ == "__main__":
    main()
