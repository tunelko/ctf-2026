# Exclusive Key - XOR Challenge Writeup

## Challenge Description
We XOR encrypted this file, but forgot to save the password. Can you recover the password for us and find the flag?

## Files
- `exclusive_key` - XOR encrypted file (111,113 bytes)

## Solution

### Step 1: Known Plaintext Attack with Flag Format

Since CTF flags typically follow the format `247CTF{...}`, we can use this as known plaintext to discover what the original file might be:

```python
from itertools import cycle

def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])

with open('exclusive_key', 'rb') as f:
    encrypted = f.read()

# XOR with known flag prefix
key = "247CTF{".encode()
result = xor(encrypted, cycle(key))
print(result[:50])
# Output: b'<!DOCTY...'
```

This reveals the plaintext starts with `<!DOCTY` - indicating an HTML file starting with `<!DOCTYPE html>`.

### Step 2: Identify the HTML Structure

By testing with `<!DOCTYPE html>`, we can recover more of the password:

```python
key = "<!DOCTYPE html>".encode()
result = xor(encrypted, cycle(key))
print(result[:20])
# Output: b'247CTF{XXXXXXXX...'
```

This confirms the password is the flag itself, and we can see it starts with `247CTF{...`.

### Step 3: Determine Full HTML Pattern

The decrypted content contains fragments like `"client-js"` which is characteristic of **Wikipedia** pages. Wikipedia HTML starts with:

```html
<!DOCTYPE html>
<html class="client-nojs
```

This is exactly **40 characters** (including the newline), which matches the expected flag length.

### Step 4: Recover the Full Flag

```python
from itertools import cycle

def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])

with open('exclusive_key', 'rb') as f:
    encrypted = f.read()

# Wikipedia HTML structure - exactly 40 characters
html_key = '<!DOCTYPE html>\n<html class="client-nojs'.encode()

# XOR to recover the password/flag
flag = xor(encrypted[:40], html_key)
print(flag.decode())
```

### Step 5: Verify

Decrypting the entire file with the recovered flag reveals a Wikipedia article about "Hacker":

```python
result = xor(encrypted, cycle(flag))
with open('decrypted.html', 'wb') as f:
    f.write(result)
# Result: Valid HTML - Wikipedia "Hacker" article
```

## Flag
```
247CTF{cb82a21bXXXXXXXXXXXXXXXXc2b48f47}
```

## Lessons Learned

1. **Known Plaintext Attack**: Using known parts of plaintext (flag format, file signatures) to recover XOR keys
2. **XOR Properties**: `A XOR B = C` implies `A XOR C = B` and `B XOR C = A`
3. **Repeating Key XOR**: The password repeats cyclically across the file
4. **File Format Recognition**: Identifying file types from partial decryption helps narrow down the plaintext structure

## Solve Script

```python
from itertools import cycle

def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])

with open('exclusive_key', 'rb') as f:
    encrypted = f.read()

# Wikipedia HTML header is exactly 40 chars
html = '<!DOCTYPE html>\n<html class="client-nojs'.encode()
flag = xor(encrypted[:40], html)
print(f"Flag: {flag.decode()}")

# Decrypt and save
result = xor(encrypted, cycle(flag))
with open('decrypted.html', 'wb') as f:
    f.write(result)
```
