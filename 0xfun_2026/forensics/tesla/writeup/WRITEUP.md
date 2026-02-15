# Tesla - 0xfun CTF

## Challenge Information
- **Category**: Forensics
- **Difficulty**: Medium
- **Points**: 250
- **Topic**: Flipper Zero BadUSB Script Deobfuscation

## Challenge Description
> Flipper Zero, often referred to as a hacking device, includes applications such as RF, BadUSB, UART...

## Provided Files
- `Tesla.sub` (26,449 bytes)

## Initial Analysis

### File Identification
```bash
$ file Tesla.sub
Tesla.sub: ASCII text, with very long lines (26347), with no line terminators

$ head -5 Tesla.sub
Filetype: Bad Usb 0xfun
Version: 1
Frequency: 433920000
Preset: FuriHalSubGhzPresetOok270Async
Protocol: RAW
```

The file appears to be a Flipper Zero script, but the `Filetype: Bad Usb 0xfun` indicates it's actually a BadUSB script (keyboard emulation), not an RF signal. The RAW_Data field contains a long binary string.

## Exploitation Steps

### Step 1: Decode Binary Data

The `RAW_Data` field contains binary encoded data (8-bit ASCII):
```python
binary_str = '01100011...'  # Extract from file
decoded = ''
for i in range(0, len(binary_str), 8):
    byte = binary_str[i:i+8]
    decoded += chr(int(byte, 2))
```

Result: A Windows batch script with heavy obfuscation.

### Step 2: Extract Obfuscation Variable

The decoded script contains:
```batch
@set "Ilc=pesbMUQl73oWnqD9rAvFRKZaf0hO5@dBN4uSzCtGjE YxITwXiVm1Jcgy26LkH8P"
```

This 64-character string is used for character substitution. The script uses patterns like `%Ilc:~29,1%` to extract the character at position 29.

### Step 3: Deobfuscate Character Substitution

Replace all `%Ilc:~N,1%` patterns with `Ilc[N]`:
```python
pattern = r'%Il.c:~(\d+),1%'
deobf = re.sub(pattern, lambda m: ilc[int(m.group(1))], decoded)
```

Result:
```batch
@echo off
powers%obfusc%hell -NoProfile -Command "[Conv%obf%ert]::ToB%obf%ase64String..."
:: 59%obf%5%obf%8051a1b1700135207%obf%46265a0e51435b36%obf%... ::
```

### Step 4: Remove Secondary Obfuscation

The script still contains `%...%` variables used to break up recognizable keywords. Remove all of them:
```python
cleaned = re.sub(r'%[^%]+%', '', deobf)
```

Cleaned result:
```batch
@echo off
powershell -NoProfile -Command "[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('i could be something to this'))"
:: 5958051a1b170013520746265a0e51435b36165752470b7f03591d1b364b501608616e ::
:: ive been encrypted many in ways::
pause
```

### Step 5: Identify Decryption Method

The PowerShell command encodes the string `'i could be something to this'` to Base64, but doesn't actually execute it - it's a hint for decryption.

The comment "ive been encrypted many in ways" suggests the hex string `5958051a1b170013520746265a0e51435b36165752470b7f03591d1b364b501608616e` is encrypted.

### Step 6: XOR Decryption

XOR the hex with the UTF-8 bytes of the key string:
```python
key_string = 'i could be something to this'
hex_bytes = bytes.fromhex('5958051a1b170013520746265a0e51435b36165752470b7f03591d1b364b501608616e')
key_bytes = key_string.encode('utf-8')

flag = bytes(hex_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(hex_bytes)))
# Result: 0xfun{d30bfU5c473_x0r3d_w1th_k3y}
```

## Flag
```
0xfun{d30bfU5c473_x0r3d_w1th_k3y}
```

## Solution Script
See `tesla_solve.py` for the complete automated solution.

## Key Takeaways

1. **Multi-layer obfuscation**: The challenge uses three layers:
   - Binary encoding (8-bit ASCII)
   - Character substitution using indexed array
   - Decoy variables to break up keywords

2. **Flipper Zero file formats**: BadUSB scripts can be disguised with RF-style headers. Always check the actual content.

3. **Hidden in plain sight**: The XOR key was visible in the deobfuscated PowerShell command, but the Base64 encoding was a red herring - only the UTF-8 bytes were needed.

4. **Comment analysis**: Critical data (the encrypted hex) was hidden in batch comments (`::`), a common technique in script-based challenges.

## Files
- `Tesla.sub` - Original challenge file
- `tesla_solve.py` - Automated solution script
- `deobfuscated.bat` - Intermediate deobfuscated script
- `TESLA_WRITEUP.md` - This writeup
