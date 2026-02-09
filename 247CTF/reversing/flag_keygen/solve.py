#!/usr/bin/env python3
"""
247CTF - Flag Keygen Solver

Genera una clave de producto válida basada en el algoritmo reverseado.

Algoritmo:
1. Longitud = 32 caracteres
2. Cada caracter en rango '@' (0x40) a 'Z' (0x5A)
3. transform(c) = c + 181 si c <= 'M', sino c + 177
4. sum = 247; for i in 1..31: sum += transform(key[i]) - i + 247
5. Validación: sum % 248 == transform(key[0]) == 247
"""


def transform(c):
    """Función de transformación del binario"""
    if ord(c) <= 0x4D:  # <= 'M'
        return ord(c) + 0xB5  # + 181
    else:
        return ord(c) + 0xB1  # + 177


def verify(key):
    """Verifica si una clave es válida según el algoritmo del binario"""
    if len(key) != 32:
        return False, "Longitud incorrecta"

    for c in key:
        if not (ord("@") <= ord(c) <= ord("Z")):
            return False, f"Caracter inválido: {c}"

    s = 0xF7  # 247
    for i in range(1, 32):
        s += transform(key[i]) - i + 0xF7

    t0 = transform(key[0])
    mod = s % 0xF8

    if mod == t0 == 0xF7:
        return True, f"sum={s}, mod={mod}"
    return False, f"sum={s}, mod={mod}, transform(key[0])={t0}"


def generate_key():
    """
    Genera una clave válida.

    Restricciones:
    - key[0] debe tener transform = 247 → 'B'
    - sum(transform(key[1:32])) % 248 = 31

    Solución:
    - 31 '@' dan suma 7595, mod 248 = 155
    - Necesitamos 124 para llegar a mod 31
    - 5*'Z'(+22) + 1*'N'(+10) + 4*'A'(+1) = 124
    """
    key0 = "B"  # transform('B') = 66 + 181 = 247
    key_rest = "Z" * 5 + "N" + "A" * 4 + "@" * 21
    return key0 + key_rest


def main():
    key = generate_key()
    valid, details = verify(key)

    print(f"[+] Product Key: {key}")
    print(f"[+] Length: {len(key)}")
    print(f"[+] Valid: {valid}")
    print(f"[+] Details: {details}")

    # Mostrar breakdown de la clave
    print(f"\n[*] Breakdown:")
    print(f"    key[0] = '{key[0]}' → transform = {transform(key[0])}")

    total = sum(transform(c) for c in key[1:])
    print(f"    sum(transform(key[1:32])) = {total}")
    print(f"    {total} % 248 = {total % 248}")

    # Instrucciones de uso
    print(f"\n[*] Para obtener el flag:")
    print(f'    echo "{key}" | nc 68630a027d8b32b7.247ctf.com 50231')


if __name__ == "__main__":
    main()
