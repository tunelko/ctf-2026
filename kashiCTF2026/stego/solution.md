# Conquer (Stego)

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | KashiCTF 2026                  |
| Categoría   | stego                          |
| Puntos      | 100                            |

## Descripcion
> I like to save my files as pdfs. Kashi kings hate 184

## TL;DR
PPM image saved as .pdf. Header declares 150 rows but file contains 185 rows. Flag in hidden 35 extra rows.

## Proceso

```bash
file flag.pdf  # → Netpbm image data, P6, 284x150

python3 -c "
# Header: P6, 284x150, max=255 → expected 127800 bytes pixel data
# Actual: 157620 bytes → 29820 extra bytes = 35 hidden rows
# Render rows 150-185 to see the flag
"
```

The "hate 184" hint was a red herring (or secondary). The real trick: PPM header says 150 rows, but the file has 185 rows of pixel data. Standard viewers only render the declared 150 rows, hiding the last 35 which contain the flag.

## Flag
```
kashiCTF{iLOVEkashi}
```

## Key Lessons
- Always check actual file size vs declared dimensions in image formats
- PPM/PGM/PBM headers are trivially editable — reducing declared height hides data at the end
- `file` command shows declared dimensions; compare with actual byte count to detect hidden data
