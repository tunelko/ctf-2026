# see-two — BSidesSF 2026 (RE Cloud, 785pts)

## TL;DR

Go C2 implant with hardcoded blocklisted UUID. Patch the UUID to register a new client, use `list files [uuid]` to enumerate exfiltrated files for all clients, then download them directly from the public-read GCS bucket.

## Flag

```
CTF{c2itthatth3fil3sar3f0und}
```

## Description

Given `client_alice`, a 46MB Go ELF binary — an implant for a custom C2 framework called "SEE-TWO". The binary connects via gRPC+mTLS to a server and can register, heartbeat, list clients/files, and upload files to a GCS bucket.

## Analysis

### Binary identification

```
ELF 64-bit, Go, not stripped, with debug_info
Build flags: -X main.builtClientUUID=21f96e72-4e88-49a4-a1ff-2000db761089
             -X main.builtServerAddr=see-two-f2136f52.challenges.bsidessf.net:8443
```

### Key components

- **mTLS**: Embedded CA cert (CN=see-two-ca), client cert (CN=see-two-client), and client private key
- **GCS bucket**: `see-two-ctf-artifacts` — objects are publicly readable but not listable
- **REPL commands**: `help`, `list clients`, `list files [uuid]`, `write file <path>`, `exit`

### Problem: Original UUID is blocklisted

Running the binary as-is fails:
```
register failed: This client has been blocklisted and cannot communicate with the server
```

## Exploit Steps

1. **Patch UUID** — The hardcoded UUID appears 3 times in the binary. Replace all occurrences with a fresh UUID:
   ```python
   data = open('client_alice', 'rb').read()
   patched = data.replace(b'21f96e72-4e88-49a4-a1ff-2000db761089',
                           b'6c4ccb7e-c5e4-4cc4-bfda-486764037078')
   open('client_patched', 'wb').write(patched)
   ```

2. **Connect and enumerate** — Run the patched client, register successfully, then list all clients and their files:
   ```
   > list clients    → ~100+ registered clients, 4 original: alice, bob, charlie, danny
   > list files 21f96e72-...   → alice's 24 files
   > list files a2396e8c-...   → bob's 23 files
   > list files 8990c14f-...   → charlie's 27 files
   > list files 6cd5839d-...   → danny's 30 files
   ```

3. **Download files from GCS** — Objects are at `https://storage.googleapis.com/see-two-ctf-artifacts/{uuid}/{hash}.txt` and publicly readable despite the bucket not being listable.

4. **Find the flag** — Hidden at the end of bob's `personal_note_week5.txt` and danny's `personal_note_week6.txt`:
   ```
   Date: 2026-02-02
   Project Notes:
   - Build a tiny CLI to track weekly goals.
   ...
   - CTF{c2itthatth3fil3sar3f0und}
   ```

## Key Insights

- "see-two" = C2 (command and control)
- The flag `c2itthatth3fil3sar3f0und` = "C2 it that the files are found"
- GCS bucket has public object reads but no list permission — you need the server's file listing to get the object paths
- The `list files [uuid]` command accepts any UUID, allowing cross-client file enumeration (IDOR)
- The flag was in multiple clients' files to ensure it could be found regardless of which UUID you checked
