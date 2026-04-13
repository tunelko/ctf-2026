# Ancient Mystery

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | KashiCTF 2026                  |
| Categoría   | crypto                         |
| Dificultad  | Easy                           |
| Puntos      | 100                            |
| Autor       | 1C3_B34R                       |

## Descripcion
> A secret message has been passed down through generations since the time of the great Mahabharata war. Legend says that every 64 years, the keepers of this secret would encode the message once more to protect it from those who might seek to misuse its power. The message has traveled through 3136 years of history, from the ancient battlefields of Kurukshetra in 3136 BCE to the dawn of the Common Era.

## TL;DR
Base64 decode 49 veces (3136 años / 64 años por ronda = 49 rondas).

## Analisis inicial

```bash
$ wc -c secret_message.txt
61801724  # ~62 MB de base64
$ head -c 100 secret_message.txt
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVjAx...
```

62 MB de texto base64. La descripción da las pistas:
- **64** años → base**64**
- **3136** años de historia / **64** años por ronda = **49** rondas de encoding

## Proceso de resolucion

```python
import base64

with open("secret_message.txt", "r") as f:
    data = f.read().strip()

for i in range(49):
    data = base64.b64decode(data).decode()

print(data)
# flag{th3_s3cr3t_0f_mah4bh4r4t4_fr0m_3136_BCE}
```

Evolución del tamaño:
```
Ronda  1: 46,351,292 bytes
Ronda 11:  2,610,200 bytes
Ronda 21:    146,988 bytes
Ronda 31:      8,272 bytes
Ronda 41:        460 bytes
Ronda 49:         49 bytes (flag)
```

## Flag
```
kashiCTF{th3_s3cr3t_0f_mah4bh4r4t4_fr0m_3136_BCE}
```
(Flag original `flag{...}`, convertida a formato `kashiCTF{...}` según instrucciones)

## Key Lessons
- Cuando la descripción menciona números específicos, buscar relaciones matemáticas con el encoding
- base64 expande ~4/3x por ronda — 49 rondas sobre un flag de ~50 bytes = ~62 MB
