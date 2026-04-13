# Lost and Found — UMassCTF 2026 (Forensics)

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | UMassCTF 2026                  |
| Categoría   | Forensics / Crypto             |
| Dificultad  | Medium                         |
| Puntos      | 218                            |
| Solves      | 85                             |

## Descripción

> Help! I was running commands on my ultra minimalistic Linux VM when I installed my favorite package and everything turned into nonsense!
>
> Hint 1: Credentials are root, empty password
> Hint 2: the command 'history' does not print the history file

## TL;DR

Alpine Linux VM image con un repo git en `/home/` cifrado con `cargo install xor` (crate xor v1.4.5, modo recursivo). El usuario borró el comando xor del historial. Key de 165 bytes derivada de archivos git con contenido predecible (description, config, reflog). Flag en el mensaje del `git stash` commit.

## Análisis

### 1. Montar la imagen

```bash
tar xf ctf-vm.ova
gunzip ctf-vm-disk1.vmdk.gz
qemu-img convert -f vmdk -O raw ctf-vm-disk1.vmdk ctf-vm-disk1.raw
fdisk -l ctf-vm-disk1.raw   # 3 partitions: boot, swap, root
losetup -fP ctf-vm-disk1.raw
mount /dev/loop0p3 /mnt/ctf-root
mount /dev/loop0p1 /mnt/ctf-boot
```

### 2. Shell history (`.ash_history`)

El hint dice que `history` no imprime el historial. En Alpine (ash shell), el historial está en `~/.ash_history`:

```
cargo install xor
xor --help
git init .
git add .
git commit -m "a bunch of nonsense"
echo "hmmm" > nonsuspiciousatall.txt
git add .
echo "ajfesidpiunvzcoixuiuwjenfksdlzxjol" > ./*/red-herring
for f in $(find . -type d); do echo "kajdsfojczvioxjoij3" >> $f/red-herring; done
xor --help
ls 5457501C/
vi .ash_history    ← editó el historial para borrar el comando xor con la clave
```

Secuencia: git init en /home/ → commit → red-herring files → `xor -r /home/ -k <key>` (borrado del historial)

### 3. Identificar el cifrado

Directorios en `/home/` con nombres hex: `5457501C`, `00485A020319010200`, etc. El crate `xor` con `-r` (recursivo):
- XOR filenames con la clave, luego hex-encode
- XOR file content con la misma clave (repeating)

### 4. Derivar la clave XOR

**Paso 1**: `red-herring` (11 bytes) → hex `08555D451D131A075A5D0E` → XOR → primeros 11 bytes de clave = `z09huvhu33i`

**Paso 2**: `.git/description` (73 bytes de contenido predecible) → 73 bytes de clave

**Paso 3**: `.git/config` (92 bytes, git init default) → 92 bytes de clave

**Paso 4**: `.git/logs/HEAD` (reflog, formato predecible con root@localhost.localdomain) → 171 bytes de clave

**Paso 5**: Los últimos 6 bytes (`z09huv`) coinciden con los primeros 6 → **período = 165 bytes**

Clave completa (165 bytes):
```
z09huvhu33i3bbuvuxzciohzcxviho3wryyudsfyuzcvxhyuhyuwrhyufdsuhhyuzvxcijlfkdasjknvoxzcihuwefijdsokncvlxznouhwe8dsoiljkcxnnnwue?edsp8oicjxlvnbefhsoaduijkcvxnbywu9e8f0d9
```

### 5. Descifrar objetos git

Con la clave de 165 bytes, descifrar los objetos git (zlib comprimidos). El commit principal apunta a un tree con solo directorios de red-herring. Pero hay un **git stash** (refs/stash) apuntando al commit `55a10e0874b6d37a8b9c2d70468d91f5b8c78cf5`.

El mensaje del stash commit:

```
On master: You found me! UMASS{h3r35_7h3_c4rg0_vr00m}
```

## Flag

```
UMASS{h3r35_7h3_c4rg0_vr00m}
```

## Key Lessons

- **Archivos git con contenido predecible**: `description`, `config`, `HEAD`, reflog tienen formato conocido → known-plaintext attack contra XOR
- **Repetición de clave XOR**: si la clave se repite, basta encontrar suficiente plaintext conocido para cubrir un período completo
- **git stash como hiding spot**: stash commits no aparecen en `git log` pero están en los objetos
- **El historial editado con `vi`**: el usuario borró el comando xor del historial, pero la clave se puede recuperar del known-plaintext
- **Período de la clave**: detectar que los últimos N bytes de la clave derivada coinciden con los primeros N confirma el período
