# Git Your Works

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | KashiCTF 2026                  |
| Categoría   | misc                           |

## Descripcion
> git your works

## TL;DR
Flag hidden as base64-encoded directory name inside `.git/objects/`. `git fsck` reveals the corrupted path, concatenating the parent dir (`a2`) with the directory name gives valid base64 that decodes to the flag.

## Proceso

### Paso 1: Clone and fetch updated repo
```bash
git clone https://github.com/Aerex0/git-your-works.git
cd git-your-works
git log --oneline | head -5
# cab5250 commit 1100
# b1f0179 commit 1099
# ...
git log --oneline | wc -l
# 1100
```

Repo has 1100 commits, each one sets `x = N` in `code.py`. Two new commits added `chall.zip` (a bundled git repo).

### Paso 2: Extract the challenge repo
```bash
git checkout origin/main -- chall.zip
unzip chall.zip -d challenge/
cd challenge/
```

Same 1100 commits inside. Working tree modified to `print("hey bitch!!, wassup")`. Also found `.git/opencode` containing the hash of commit 1 — a red herring.

### Paso 3: Recon
```bash
cat code.py
# print("hey bitch!!, wassup")
git status
# modified: code.py (unstaged change from x = 1100)
git log --oneline | wc -l
# 1100
git branch -a
# * main, remotes/origin/main
git stash list
# (empty)
git reflog | head -5
# cab5250 HEAD@{0}: Branch: renamed refs/heads/master to refs/heads/main
# cab5250 HEAD@{2}: commit: commit 1100
# ...
cat .git/opencode
# 84dfe63842daad9340d8bdcdc7abbf3b9f34428f  (hash of commit 1 — red herring)
```

### Paso 4: Check git integrity
```bash
git fsck --unreachable --no-reflogs
# bad sha1 file: .git/objects/a2/FzaGlDVEZ7bDM0bl9nMTdfMW43M3JuNGw1fQo=
```

`git fsck` reports a corrupted object — the filename is clearly not a valid hex SHA1. It's actually a directory (not a file) inside `objects/a2/`.

### Paso 5: Decode
The git objects path convention is `objects/XX/YYYYYY...` where `XX` is the first 2 hex chars of SHA1. Here `a2` is the directory prefix and the non-hex name is a base64 fragment.

Concatenating: `a2` + `FzaGlDVEZ7bDM0bl9nMTdfMW43M3JuNGw1fQo=` = `a2FzaGlDVEZ7bDM0bl9nMTdfMW43M3JuNGw1fQo=`

```bash
echo "a2FzaGlDVEZ7bDM0bl9nMTdfMW43M3JuNGw1fQo=" | base64 -d
# kashiCTF{l34n_g17_1n73rn4l5}
```

Verification:
```bash
python3 -c "import base64; print(base64.b64decode('a2FzaGlDVEZ7bDM0bl9nMTdfMW43M3JuNGw1fQo='))"
# b'kashiCTF{l34n_g17_1n73rn4l5}\n'
```

## Flag
```
kashiCTF{l34n_g17_1n73rn4l5}
```

## Key Lessons
- `git fsck` reports invalid/corrupted objects — first tool to run on suspicious git repos
- Git object paths use `objects/XX/YYYY...` with hex SHA1 names — any non-hex filename is immediately suspicious
- The `a2/` directory prefix was chosen so that concatenation with the filename produces valid base64 (`a2` is the base64 encoding start of `kashiCTF`)
- The 1100 dummy commits and `.git/opencode` file were distractions — the flag was in the filesystem structure, not in commit content
- Always enumerate `.git/objects/` for anomalous filenames in forensics/misc git challenges
