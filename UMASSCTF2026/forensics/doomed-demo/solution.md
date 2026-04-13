# Doomed Demo

| Campo | Valor |
|-------|-------|
| Plataforma | UMassCTF 2026 |
| Categoría | forensics |
| Flag | `UMASS{E59FADEFEACF79B}` |

## Descripción
> I was just playing Freedoom Phase 2 version 0.13.0 and made this AWESOME demo! But something happened and the file doesn't want to work anymore...

Se proporciona un demo de Doom corrupto (`demo.lmp`) junto con Freedoom Phase 2 v0.13.0 y un archivo `WALKTHROUGH.txt` que describe la partida. El objetivo es reparar el demo y encontrar las coordenadas X,Y del jugador al final.

## TL;DR
Demo `.lmp` con header corrupto + byte 0x80 insertado + bit flips en bytes de buttons de los tics. Se usa el WALKTHROUGH para verificar y corregir las corrupciones. Coordenadas finales en fixed_t hex concatenadas.

## Análisis inicial

```bash
file demo.lmp          # data
wc -c demo.lmp         # 18635 bytes
xxd demo.lmp | head -5 # header corrupted
```

Header corrupto:
```
86 04 03 20 02 e1 aa 5f 03 00 54 01 02 80 00 00...
```

Header correcto para Chocolate Doom + Freedoom 2 + MAP03 + skill HNTR:
```
6d 01 01 03 00 00 00 00 00 01 00 00 00
```

Valores determinados del WALKTHROUGH:
- Version: 109 (0x6D) — Chocolate Doom con Doom 2 v1.9
- Skill: 1 (HNTR, "second lowest difficulty")
- Episode: 1 (Doom 2)
- Map: 3 ("Crude Processing Center" = MAP03 en Freedoom Phase 2 v0.13.0)
- Singleplayer: deathmatch=0, respawn=0, fast=0, nomonsters=0, consoleplayer=0, players=[1,0,0,0]

## Vulnerabilidad / Tipo
Forensics — reparación de formato binario (Doom .lmp demo)

## Proceso de resolución

### Paso 1: Analizar la estructura del archivo

Formato del demo de Doom:
- Header de 13 bytes: version(1) + skill(1) + episode(1) + map(1) + deathmatch(1) + respawn(1) + fast(1) + nomonsters(1) + consoleplayer(1) + playeringame(4)
- Tic data: 4 bytes por tic [forwardmove, sidemove, angleturn>>8, buttons]
- End marker: 0x80

El byte 13 es 0x80 (DEMOMARKER), lo que hace que el demo aparezca vacío — el motor lo interpreta como "0 tics".

### Paso 2: Verificar alineación de tics

```
File size: 18635 bytes
Con 13-byte header: (18635-13-1)/4 = 4655.25 — NO alinea
Con 14-byte header (skip byte 13): (18635-14-1)/4 = 4655.0 — ALINEA
```

El byte 13 (0x80) fue **insertado** como corrupción. Al eliminarlo y usar el header correcto de 13 bytes, los tics alinean perfectamente a 4655.

### Paso 3: Fix del header

```python
data = open('demo.lmp', 'rb').read()
header = bytes([0x6d, 0x01, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
fixed = header + data[14:]  # skip corrupted 14 bytes (13 header + inserted 0x80)
```

### Paso 4: Detectar desync — demo NO reproduce correctamente

Al reproducir el demo reparado en dsda-doom, el jugador termina en (496, 991) — ¡cerca del INICIO, no del EXIT! El WALKTHROUGH dice que el jugador estaba al lado del exit elevator (área ~3520-3648, -256 a -384).

**Conclusión: hay corrupción adicional en los datos de tic.**

### Paso 5: Usar el WALKTHROUGH para identificar tics corruptos

El WALKTHROUGH describe cada cambio de arma explícito. Al comparar con los BT_CHANGE en el demo:

| # | Tic | Actual | Esperado (walkthrough) | Fix |
|---|-----|--------|------------------------|-----|
| 1 | 506-508 | 0x14 (shotgun) | 0x14 (shotgun) | ✓ OK |
| 2 | 864-865 | **0x04 (fist)** | 0x0C (pistol) | bit 3 flip |
| 3 | 1007-1009 | 0x14 (shotgun) | 0x14 (shotgun) | ✓ OK |
| 4 | 1705-1707 | **0x0C (pistol)** | 0x1C (chaingun) | bit 4 flip |
| 5 | 2617-2618 | **0x24 (rocket)** | 0x14 (shotgun) | bit 5 flip |
| 6 | 3250-3252 | 0x1C (chaingun) | 0x1C (chaingun) | ✓ OK |
| 7 | 3936-3937 | **0x24 (rocket)** | 0x14 (shotgun) | bit 5 flip |

### Paso 6: Corregir los bytes de buttons corruptos

```python
fixes = [
    (864, 0x04, 0x0C),   # fist→pistol
    (865, 0x04, 0x0C),
    (1705, 0x0C, 0x1C),  # pistol→chaingun
    (1706, 0x0C, 0x1C),
    (1707, 0x0C, 0x1C),
    (2617, 0x24, 0x14),   # rocket→shotgun
    (2618, 0x24, 0x14),
    (3936, 0x24, 0x14),   # rocket→shotgun
    (3937, 0x24, 0x14),
]

for tic, old_btn, new_btn in fixes:
    btn_offset = 13 + 4*tic + 3
    fixed[btn_offset] = new_btn
```

### Paso 7: Reproducir y obtener coordenadas

Con las correcciones aplicadas, el jugador termina en:
- **X = 0x0E59FADE** (3673 map units)
- **Y = 0xFEACF79B** (-340 map units)

Distancia al exit elevator: ~91 unidades — consistente con "I hit the button, and the exit elevator descended.. but before I could get on it".

### Paso 8: Formato de la flag

El reto pide coordenadas X,Y en hexadecimal concatenadas sin prefijo 0x:
```
X = 0x0E59FADE → E59FADE
Y = 0xFEACF79B → FEACF79B
Flag = UMASS{E59FADEFEACF79B}
```

## Herramientas utilizadas
- dsda-doom (reproducción de demo con coordinate display, ghost export, análisis)
- Chocolate Doom (verificación de compatibilidad)
- Python (parsing de WAD, demo, y ghost files)
- ffmpeg (extracción de frames del video)

## Flag
```
UMASS{E59FADEFEACF79B}
```

## Key Lessons
- En demos de Doom, la corrupción puede afectar tanto el header como los datos de tic
- El WALKTHROUGH del reto es la clave para identificar tics corruptos — comparar weapon changes explícitos
- Los weapon changes producen desync porque el arma equivocada causa diferente daño → diferentes interacciones con monstruos → trayectoria divergente
- Las coordenadas de Doom son fixed_t de 32 bits (16.16 fixed-point). La flag usa el valor raw hex completo
- dsda-doom con `-export_ghost` y `-viddump` permite extraer coordenadas y verificar el gameplay frame a frame
