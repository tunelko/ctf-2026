# Plumbing

**CTF/platform:** Pragyan CTF 2026

**Category:** Forensics / Docker

**Difficulty:** Easy

**Description:** Something sensitive might have slipped through during build time, but the final container looks clean??

**Remote:** N/A (file `app.tar`)

**Flag:** `p_ctf{d0ck3r_l34k5_p1p3l1n35}`

---

## Reconnaissance

The challenge provides a Docker image exported as tar (`app.tar`, 43MB).

```bash
$ file app.tar
app.tar: POSIX tar archive
```

Image structure (OCI format):
```
blobs/
  sha256/
    [multiple hashes]
index.json
manifest.json
oci-layout
```

---

## Image Analysis

### 1. Extract and examine manifest

```bash
tar -xf app.tar
cat manifest.json | jq .
```

The manifest shows:
- **Name:** `app:latest`
- **12 layers** of filesystem
- **Config blob:** `b3f4caf17486575f3b37d7e701075fe537fe7c9473f38ce1d19d769ea393913d`

### 2. Examine image config

```bash
cat blobs/sha256/b3f4caf17486575f3b37d7e701075fe537fe7c9473f38ce1d19d769ea393913d | jq .
```

The configuration includes:
- **Base:** Python 3.10.19 on Debian
- **WorkDir:** `/app`
- **History:** Complete list of commands executed during build

---

## Vulnerability: Secret in Build History

When reviewing the `history` field of the config, we find the commands executed during image construction:

```json
{
  "created": "2025-12-23T13:05:03.988180383+05:30",
  "created_by": "COPY process.py . # buildkit"
},
{
  "created": "2025-12-23T13:05:04.038836399+05:30",
  "created_by": "COPY env /app/.env # buildkit"
},
{
  "created": "2025-12-23T13:05:04.344356969+05:30",
  "created_by": "RUN /bin/sh -c echo \"p_ctf{d0ck3r_l34k5_p1p3l1n35}X|O\" | python3 process.py # buildkit"
},
{
  "created": "2025-12-23T13:05:04.621226688+05:30",
  "created_by": "RUN /bin/sh -c rm /tmp/state_round7.bin # buildkit"
}
```

**Finding:**

The command at build time:
```bash
echo "p_ctf{d0ck3r_l34k5_p1p3l1n35}X|O" | python3 process.py
```

This command processed the flag (probably encrypted or transformed it) and saved the result in `/tmp/state_round7.bin`.

**Cleanup attempt:**
```bash
rm /tmp/state_round7.bin
```

The file was deleted in a later layer, so **it doesn't appear in the final container filesystem**. However, the **command history remains** in the image metadata.

---

## Exploitation

### Flag extraction

```bash
cat blobs/sha256/b3f4caf17486575f3b37d7e701075fe537fe7c9473f38ce1d19d769ea393913d \
  | jq -r '.history[] | select(.created_by | contains("p_ctf")) | .created_by'
```

**Output:**
```
RUN /bin/sh -c echo "p_ctf{d0ck3r_l34k5_p1p3l1n35}X|O" | python3 process.py # buildkit
```

The flag is: **`p_ctf{d0ck3r_l34k5_p1p3l1n35}`**

(The `X|O` characters at the end appear to be part of the input for `process.py`, not the flag itself)

---

## Flag

```
p_ctf{d0ck3r_l34k5_p1p3l1n35}
```

Translation: "docker leaks pipelines" (leaks = leaks, pipelines = pipes/plumbing)

---

## Lessons

### Docker Security Issue

This challenge illustrates a **common vulnerability in Docker builds**:

1. **Layer history is immutable:** All `RUN` commands are saved in image metadata, even if resulting files are deleted later.

2. **Deleting files doesn't delete history:** Doing `RUN rm /secret` does NOT erase the secret if it was created in a previous `RUN`.

3. **Secrets visible in plaintext:** Any secret passed as argument to a command (`RUN echo "secret"`) remains permanently exposed.

### Best Practices

To avoid this type of leak:

1. **Use Docker secrets or build-time secrets:**
   ```dockerfile
   # BuildKit secrets (don't remain in history)
   RUN --mount=type=secret,id=mysecret \
       cat /run/secrets/mysecret | python3 process.py
   ```

2. **Multi-stage builds:**
   ```dockerfile
   # Stage 1: process secrets
   FROM python:3.10 AS builder
   RUN echo "$SECRET" | python3 process.py > /output

   # Stage 2: only copy result
   FROM python:3.10
   COPY --from=builder /output /app/
   ```

3. **Runtime environment variables:**
   ```dockerfile
   # Don't include secrets in build, pass them at runtime
   ENV SECRET=""
   CMD python3 process.py
   ```

4. **Never hardcode secrets in Dockerfiles**

5. **Scan images with tools like:**
   - `docker history <image>` - View command history
   - `dive` - Analyze layers interactively
   - `trivy` - Vulnerability and secret scanner

---

## Tools Used

- `tar` - OCI image extraction
- `jq` - JSON parsing (manifest and config)
- Manual analysis of Docker metadata

---

## Useful Commands

```bash
# Extract image
tar -xf app.tar

# View manifest
cat manifest.json | jq .

# View full config
cat blobs/sha256/<config-hash> | jq .

# Search for secrets in history
cat blobs/sha256/<config-hash> | jq -r '.history[] | .created_by' | grep -i secret

# Extract layers
for layer in blobs/sha256/*; do
    echo "=== $layer ==="
    tar -tzf "$layer" | head
done
```
