# Kashi Ritual Ledger

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | KashiCTF 2026                  |
| Categoría   | forensics                      |
| Dificultad  | Medium                         |

## Descripcion
> An investigator recovered a Linux disk image from a manuscript ward workstation in Varanasi. The drive appears normal, but operators suspect hidden transfer records were concealed using layered steganography and encryption workflows.

## TL;DR
ext4 disk image. Extraer archivos con `debugfs`. Flag en texto plano en `stage2_ledger.txt` dentro de `.archive_payloads/`. El challenge tenía un workflow multi-stage (steghide en BMPs + AES), pero el resultado descifrado quedó en disco.

## Analisis inicial

```bash
$ file kashi_ritual_ledger.img
Linux rev 1.0 ext4 filesystem data, UUID=f83285e2-..., volume name "KASHI_LEDGER"

$ debugfs -R "ls -l /" kashi_ritual_ledger.img
     12  deleted_mail_pool/
  32769  etc/
  32770  home/
     13  challenge_runtime.json
```

Sin acceso `sudo` para montar, usamos `debugfs` para extraer todo.

### Estructura del filesystem

```
/
├── challenge_runtime.json          # Todas las claves y passphrases (!)
├── deleted_mail_pool/
│   ├── philosophy_01.eml           # Doctrina de passphrases
│   └── philosophy_02.eml           # "No guardar AES tuple cerca del payload"
├── etc/
│   ├── hostname                    # manuscript-ward
│   └── issue
└── home/pandit_ved/
    ├── .archive_payloads/
    │   ├── decoy_ledger_{a,b,c}.{enc,txt}  # Decoys
    │   ├── stage2_ledger.enc               # Payload cifrado
    │   └── stage2_ledger.txt               # ← FLAG AQUI
    ├── Browser/history.tsv
    ├── Documents/ritual_words.txt
    ├── Maildir/cur/, new/
    ├── Notes/
    │   ├── ritual_index_notes.md
    │   └── restoration_log.txt
    ├── Pictures/ward_scans/        # 4 BMPs (steganografia)
    ├── chatlogs/                   # Chats con claves stage 1
    └── .cache/.glyph_index.bin
```

## Proceso de resolucion

### Paso 1: Listar filesystem con debugfs

```bash
debugfs -R "ls -l /" kashi_ritual_ledger.img
debugfs -R "ls -l /home/pandit_ved" kashi_ritual_ledger.img
# Encontrado directorio oculto .archive_payloads
```

### Paso 2: Extraer y leer archivos clave

```bash
debugfs -R "cat /challenge_runtime.json" kashi_ritual_ledger.img
```
Contiene TODAS las claves en claro:
- Stage 1: steg passphrase `trishul-lantern-braid`, AES key `amber-ledger-lintel`
- Stage 2: steg passphrase `ghat-manjari-copper-owl`, AES key `river-ink-oblation`

### Paso 3: Leer chatlogs

```bash
debugfs -R "cat /home/pandit_ved/chatlogs/ward-chat-2026-03-11.log" ...
```
```
[22:06] ved: First lock phrase is: trishul-lantern-braid
[22:10] ved: AES-256-CBC salt=9a31f4b20d17c8ef key=amber-ledger-lintel iv=43a65f90...
[22:12] tara: those are for false ledgers and ash manifests.
```
Confirma que stage 1 es para los decoys.

### Paso 4: Extraer el payload final

```bash
debugfs -R "cat /home/pandit_ved/.archive_payloads/stage2_ledger.txt" ...
```

Output:
```
Hidden Ledger Capsule
====================
Reconstructed transfer note, sealed for tribunal audit.
Flag: kashiCTF{ledger_ashes_remember_every_ritual}
Custodian phrase seed: ghat manjari
```

Flag encontrada directamente — el operador descifró el payload y dejó el `.txt` en disco junto al `.enc`.

### Evidencia de soporte

- `restoration_log.txt`: "Uploaded four BMP captures to ward_scans" — los BMPs contienen datos steghide
- `ritual_index_notes.md`: "hidden ledger capsule is in one scan that does not open with standard phrase"
- `philosophy_02.eml`: "Do not store the second-stage AES tuple near the payload" — consejo que fue ignorado
- `ward-chat-2026-03-14.log`: "did you reuse trishul-lantern-braid on the final capsule?" / "no. final one follows my passphrase doctrine"

El workflow completo habría sido:
1. `steghide extract` de uno de los 4 BMPs con passphrase `ghat-manjari-copper-owl`
2. AES-256-CBC decrypt del extracto con key `river-ink-oblation`, salt/iv del JSON
3. Resultado = `stage2_ledger.txt`

Pero el operador dejó el resultado descifrado en disco, haciendo todo el workflow innecesario.

## Flag
```
kashiCTF{ledger_ashes_remember_every_ritual}
```

## Key Lessons
- `debugfs` es esencial cuando no hay `sudo` para montar ext4 images
- Siempre buscar archivos ocultos (`.archive_payloads`, `.cache`) — `ls -la` en debugfs
- Un `challenge_runtime.json` con todas las claves en claro es OPSEC fail del operador
- Antes de reconstruir un workflow complejo (steghide + AES), verificar si el resultado ya existe en texto plano en el filesystem
