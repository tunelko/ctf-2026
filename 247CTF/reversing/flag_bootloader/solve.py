#!/usr/bin/env python3
"""
247CTF - Flag Bootloader Solver

Analiza el bootloader de 512 bytes, extrae el código de desbloqueo
y decodifica el flag usando las claves XOR.

El bootloader valida 16 caracteres, cada uno calculado con XOR/SUB/ADD.
Cada caracter válido se usa como clave XOR para decodificar 2 bytes del flag.
"""

def extract_keys(data):
    """Extrae las claves XOR del código de validación del bootloader"""
    xor_keys = []
    i = 0x74  # Offset de la primera instrucción mov al

    while i < 0x180:
        if data[i] == 0xb0:  # mov al, imm8
            val = data[i+1]
            op = data[i+2]
            operand = data[i+3]

            # Buscar cmp [bx], al (38 07) que confirma la validación
            for j in range(i+4, min(i+10, len(data)-1)):
                if data[j] == 0x38 and data[j+1] == 0x07:
                    if op == 0x34:    # xor al, imm8
                        result = val ^ operand
                    elif op == 0x2c:  # sub al, imm8
                        result = val - operand
                    elif op == 0x04:  # add al, imm8
                        result = (val + operand) & 0xff
                    else:
                        break
                    xor_keys.append(result)
                    break
        i += 1

    return xor_keys


def decode_flag(data, xor_keys):
    """Decodifica el flag usando las claves XOR extraídas"""
    flag_start = 0x1aa  # Offset del flag codificado

    # El flag empieza con "247CTF{" (no codificado)
    flag = bytearray(b"247CTF{")

    # Parte codificada empieza después de "247CTF{"
    encoded = data[flag_start + 7:]

    # Cada clave XOR decodifica 2 bytes consecutivos
    for i, key in enumerate(xor_keys):
        flag.append(encoded[i*2] ^ key)
        flag.append(encoded[i*2 + 1] ^ key)

    flag.append(ord('}'))
    return flag.decode()


def main():
    with open('flag.com', 'rb') as f:
        data = f.read()

    print(f"[*] Bootloader size: {len(data)} bytes")
    print(f"[*] Boot signature: {data[-2]:02x} {data[-1]:02x}")

    # Extraer claves
    xor_keys = extract_keys(data)
    unlock_code = ''.join(chr(k) for k in xor_keys)

    print(f"\n[+] Unlock code ({len(unlock_code)} chars): {unlock_code}")
    print(f"[+] XOR keys: {[hex(k) for k in xor_keys]}")

    # Decodificar flag
    flag = decode_flag(data, xor_keys)
    print(f"\n[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
