# Slavery (Forensics)

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | KashiCTF 2026                  |
| Categoría   | forensics                      |

## Descripcion
> Endless text. Endless effort. Endless suffering. Somewhere inside this Sanskrit manuscript, a flag has been hidden — buried deep enough to make anyone give up before reaching it.

## TL;DR
Tiny 928x87 image hidden on page 269 of a 408-page scanned Sanskrit PDF. Found by extracting all images and filtering by anomalous dimensions.

## Proceso

```bash
# Extract all images, find anomalous sizes
python3 -c "
import fitz
doc = fitz.open('file.pdf')
for i in range(doc.page_count):
    for img in doc[i].get_images():
        pix = fitz.Pixmap(doc, img[0])
        if pix.width < 100 or pix.height < 100:
            print(f'Page {i+1}: {pix.width}x{pix.height}, xref={img[0]}')
"
# Result: Page 269, xref=828, 928x87
# Extract and view:
pix = fitz.Pixmap(doc, 828)
pix.save("hidden.png")
```

All 408 pages have full-page scans (~600-1100 x ~1100-1400). One outlier: 928x87 on page 269.

## Flag
```
kashiCTF{1r0nhex_1s_n07_4_m4n}
```

## Key Lessons
- For large PDFs: extract ALL images and sort by dimension anomalies rather than viewing every page
- `fitz.Pixmap(doc, xref)` extracts images directly by xref — no need to render pages
