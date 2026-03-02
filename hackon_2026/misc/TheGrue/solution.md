# TheGrue2 - Misc Challenge

**Category:** Misc
**CTF:** HackOn CTF
**Flag:** `HackOn{3l_grU3s0}`
**Difficulty:** Easy

---

## Initial Analysis

```bash
ls -la "TheGrue 3D GamePwn IL2CPP/"
```

```
ctf-thegrue.exe               # Unity executable (667KB)
GameAssembly.dll              # C# → C++ compiled via IL2CPP (41MB)
UnityPlayer.dll               # Unity engine (35MB)
ctf-thegrue_Data/
├── global-metadata.dat       # IL2CPP metadata
├── level0, level1, level2    # Scene files
└── *.assets                  # Asset bundles
```

Unity game compiled with **IL2CPP** (Intermediate Language To C++). IL2CPP converts C# to native C++, but **assets** (scenes, dialogues, textures) remain as readable data files.

---

## Vulnerability: Flag in Unencrypted Assets

### String search

```bash
cd "ctf-thegrue_Data"
strings level* | grep -i "HackOn{"
```

**Output**:
```
HackOn{3l_grU3s0}
```

Flag found in **`level2`** (scene file) in plaintext.

### Dialogue context

```
No se como acabo siempre encerrado con TheGrue...
Menos mal que esta el de las Manos para protegerme.

El de las Manos
Hmm?
HackOn{3l_grU3s0}
```

An NPC called "El de las Manos" reveals the flag in level 2.

---

## Exploit (`solve.sh`)

```bash
#!/bin/bash
# TheGrue2 - Flag extraction from Unity level files
GAME_DIR="TheGrue 3D GamePwn IL2CPP/ctf-thegrue_Data"

for level in "$GAME_DIR"/level*; do
    result=$(strings "$level" | grep -i "HackOn{")
    if [ -n "$result" ]; then
        echo "[+] FLAG in $(basename $level): $result"
        exit 0
    fi
done
echo "[-] No flag found"
```

```bash
bash solve.sh
# [+] FLAG in level2: HackOn{3l_grU3s0}
```

---

## Cultural Reference

**The Grue** is a creature from classic text adventure games (Zork, 1980):

> *"It is pitch black. You are likely to be eaten by a grue."*

The flag `3l_grU3s0` = "el grueso" in leet speak. Double wordplay: "el grue so" / "el grueso".

---

## Key Lessons

1. **Unity IL2CPP doesn't encrypt assets**: Scenes, dialogues and textures are readable with `strings`.
2. **Simple tools first**: `strings` + `grep` solved the challenge without needing Il2CppDumper, Ghidra, or running the game.
3. **Assets > Code**: In Unity games, assets contain the useful information; compiled code rarely hides flags.

### Tools NOT needed

- Il2CppDumper, dnSpy, Ghidra, IDA, AssetStudio, running the game
- Only used: `strings` + `grep`
