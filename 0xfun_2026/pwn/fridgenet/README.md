# FridgeNet - PWN Challenge

## Información del Reto

- **Categoría:** PWN / Binary Exploitation
- **Dificultad:** Fácil
- **Servicio:** `nc chall.0xfun.org 63809`

## Descripción

We've experienced a data breach! Our forensics team detected unusual network activity originating from our new smart refrigerator. It turns out there's an old debugging service still running on it. Now it's your job to figure out how the attackers gained access to the fridge!

## Archivos

- `vuln` - Binario vulnerable (ELF 32-bit)
- `exploit.py` - Exploit funcional
- `WRITEUP.md` - Writeup completo con análisis detallado

## FLAG

```
0xfun{4_ch1ll1ng_d1sc0v3ry!p1x3l_b3at_r3v3l4t1ons_c0d3x_b1n4ry_s0rcery_unl3@sh3d!}
```

## Quick Start

```bash
# Analizar el binario
checksec vuln
r2 -A vuln

# Ejecutar el exploit
python3 exploit.py
```

## Vulnerabilidad

Buffer overflow en función `set_welcome_message()` usando `gets()` sin límite.

## Técnica

ret2plt: Redirigir ejecución a `system@plt` con argumento `/bin/sh` que ya existe en el binario.
