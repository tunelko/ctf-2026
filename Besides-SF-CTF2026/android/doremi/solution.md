# DoReMi

| Campo       | Valor              |
|-------------|--------------------|
| Plataforma  | BSidesSF 2026      |
| Categoría   | Mobile 101         |
| Dificultad  | Medium             |
| Puntos      | 1000               |
| Autor       | itsc0rg1           |

## Descripción
> Can you find the flag on the app?

## TL;DR
Flag is encoded as SVG vector path data in the APK's drawable XML resources. Rendering the paths reveals text characters that spell out the flag.

## Análisis inicial

```bash
file doremi.apk
# Zip archive data (standard APK)

unzip -o doremi.apk -d apk_extracted
# 5 DEX files (classes.dex through classes5.dex), Kotlin-based Compose app
```

Package: `com.bsidessf.doremi` — a music-themed Android app.

Searching DEX files for app-specific strings:

```bash
strings apk_extracted/classes4.dex | grep -i "bsidessf\|doremi\|image\|drawable"
```

Key findings in `classes4.dex` (the main app code):
- `MainActivity` and `FrameActivity` — two activities
- `imageFiveCTF`, `imageFourCTF`, `imageOneCTF`, `imageThreeCTF`, `imageTwoCTF` — 5 image views
- `aria_with_bg`, `cadence_with_bg`, `lyra_with_bg`, `sonnet_with_bg` — drawable resources with music-themed names
- `rightPitch`, `buttonEnter` — UI interaction elements
- `drawableIds`, `imageViewIds` — arrays linking drawables to views

## Proceso de resolución

### Paso 1: Decode APK resources

```bash
apktool d doremi.apk -o apktool_out -f
```

Found 6 music-themed vector drawables in `res/drawable/`:
- `aria.xml`, `cadence.xml`, `lyra.xml`, `rhythm.xml`, `sonnet.xml`, `tempo.xml`
- Plus `_with_bg` variants of each

### Paso 2: Examine vector drawables

Each drawable is an Android `<vector>` with SVG-style `<path>` elements containing `pathData` attributes:

```xml
<!-- aria.xml excerpt -->
<vector android:height="1920.0dip" android:width="1080.0dip" ...>
    <path android:fillColor="#ff551f7a"
          android:pathData="M213.5 103L227.5 103L238.5 106Q248.3 110.3 ..." />
    <path android:fillColor="#ff8dc63f"
          android:pathData="M247 248L281.5 248L282.5 249..." />
</vector>
```

Two color groups:
- **Purple (`#ff551f7a`)**: flag text
- **Green (`#ff8dc63f`)**: musical note names (Do, Re, Mi, Fa, Sol)

### Paso 3: Render the vector paths

Used matplotlib to render all SVG path data from all 6 drawables:

```python
import re, matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.path import Path as MPath
from matplotlib.patches import PathPatch

def parse_svg_path(d):
    """Parse M, L, Q, Z SVG commands"""
    vertices, codes = [], []
    tokens = re.findall(r'[MLQCZ]|[-+]?\d*\.?\d+', d)
    i = 0
    while i < len(tokens):
        cmd = tokens[i]
        if cmd == 'M':
            vertices.append((float(tokens[i+1]), float(tokens[i+2])))
            codes.append(MPath.MOVETO); i += 3
        elif cmd == 'L':
            vertices.append((float(tokens[i+1]), float(tokens[i+2])))
            codes.append(MPath.LINETO); i += 3
        elif cmd == 'Q':
            vertices.append((float(tokens[i+1]), float(tokens[i+2])))
            codes.append(MPath.CURVE3)
            vertices.append((float(tokens[i+3]), float(tokens[i+4])))
            codes.append(MPath.CURVE3); i += 5
        elif cmd == 'Z':
            vertices.append(vertices[0] if vertices else (0,0))
            codes.append(MPath.CLOSEPOLY); i += 1
        else: i += 1
    return vertices, codes

fig, ax = plt.subplots(1, 1, figsize=(12, 22))
for name in ['aria', 'cadence', 'lyra', 'rhythm', 'sonnet', 'tempo']:
    with open(f'apktool_out/res/drawable/{name}.xml') as f:
        content = f.read()
    for color_hex, path_d in re.findall(r'fillColor="(#\w+)".*?pathData="([^"]+)"', content):
        vertices, codes = parse_svg_path(path_d)
        if vertices and len(vertices) == len(codes):
            patch = PathPatch(MPath(vertices, codes),
                            facecolor='#'+color_hex[3:], edgecolor='none', alpha=0.9)
            ax.add_patch(patch)
ax.set_xlim(0, 1080); ax.set_ylim(1920, 0); ax.set_aspect('equal')
plt.savefig('flag_full.png', dpi=100)
```

### Paso 4: Read the flag

The rendered image shows text at 6 vertical positions, each from a different drawable:

| Drawable | Purple text (flag) | Green text (music) |
|----------|-------------------|-------------------|
| aria     | `CTF{`            | `Do`              |
| cadence  | `sl1ce`           | `Re`              |
| lyra     | `and`             | `Mi`              |
| rhythm   | *(decoration)*    | `Welcome to Do Re Mi Fa Sol` |
| sonnet   | `d1c3`            | `Fa`              |
| tempo    | `th3m}`           | `Sol`             |

Reading the purple text in order: **`CTF{sl1ceandd1c3th3m}`**

## Flag
```
CTF{sl1ceandd1c3th3m}
```

## Key Lessons
- **Vector drawables as steganography**: Android vector XML files contain SVG path data that can encode arbitrary shapes — including text characters. This isn't visible without rendering the paths.
- **Look beyond code**: The flag wasn't in strings, code logic, or network traffic — it was in the visual assets themselves.
- **apktool over jadx for resources**: jadx focuses on Java decompilation; apktool properly decodes binary XML resources back to readable format, which was essential here.
- **Multiple resource files**: The flag was split across 6 separate drawable files, requiring all to be combined to read the full message.

## Referencias
- Android Vector Drawable format: `<vector>` with SVG-like `<path>` elements
- "slice and dice them" — the flag's meaning, fitting the music theme (cutting/arranging musical phrases)
