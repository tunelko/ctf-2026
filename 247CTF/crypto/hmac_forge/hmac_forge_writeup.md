# Forgeable HMAC - Hash Length Extension Attack Writeup

## Challenge Description
Can you abuse the flag HMAC implementation and forge a valid request?

## Analysis

### The Vulnerable Code
```php
<?php
require_once('flag.php');

function flag_hash($flag, $user) {
    return hash("sha256", $flag . strrev($user));
}

if (isset($_GET['user'], $_GET['hmac'])) {
    if ((int)$_GET['user'] !== 247 && flag_hash($flag, $_GET['user']) === $_GET['hmac']) {
        echo $flag;
    }
} else {
    echo flag_hash($flag, 247);
}
```

### The Vulnerability
The "HMAC" implementation is **not a true HMAC** - it simply concatenates the secret (flag) with user input and hashes it:
```
hash(flag || strrev(user))
```

This is vulnerable to a **Hash Length Extension Attack** because SHA-256 uses Merkle-Damgård construction.

### What We Know
- `hash(flag || "742")` = `941f351a0c83589622bb5b81cddb18f4a74a7e877cd9b9548e37fec58370fc3e`
- Flag format: `247CTF{32-hex-chars}` = 40 bytes
- We need to forge a valid hash for a user value other than 247

## Hash Length Extension Attack

### How It Works
SHA-256 processes data in 64-byte blocks with padding. The final hash state can be used as the starting state for additional data:

1. Original: `H(flag || "742" || padding)`
2. Extended: `H(flag || "742" || padding || extension)`

We can compute the extended hash **without knowing the flag** by:
1. Using the known hash as the initial state
2. Processing our extension through SHA-256's compression function

### The Attack
1. **Known hash**: Result of `H(flag || "742")`
2. **Key length**: 40 bytes (flag length)
3. **Extension**: Any data (we use "1")
4. **New message**: `flag || "742" || padding || "1"`

The server computes: `hash(flag || strrev(user))`

So we need: `strrev(user) = "742" || padding || "1"`

Which means: `user = strrev("742" || padding || "1") = "1" || reversed_padding || "247"`

## Solution

```python
import struct
import requests

def sha256_padding(message_len):
    """Generate SHA-256 padding"""
    padding = b'\x80'
    padding += b'\x00' * ((55 - message_len) % 64)
    padding += struct.pack('>Q', message_len * 8)
    return padding

def hash_extend(original_hash, original_data, key_length, append_data):
    """Perform hash length extension"""
    state = struct.unpack('>8I', bytes.fromhex(original_hash))
    original_len = key_length + len(original_data)
    padding = sha256_padding(original_len)
    new_suffix = original_data + padding + append_data

    # Continue SHA-256 compression with extension
    extended_len = original_len + len(padding)
    append_padded = append_data + sha256_padding(extended_len + len(append_data))

    # Process through SHA-256 compression function
    for i in range(0, len(append_padded), 64):
        block = append_padded[i:i+64]
        if len(block) == 64:
            state = sha256_compress(state, block)

    new_hash = ''.join(f'{x:08x}' for x in state)
    return new_hash, new_suffix

# Attack parameters
original_hash = "941f351a0c83589622bb5b81cddb18f4a74a7e877cd9b9548e37fec58370fc3e"
original_data = b"742"
key_length = 40
append_data = b"1"

# Forge the hash
new_hash, new_suffix = hash_extend(original_hash, original_data, key_length, append_data)

# Reverse for strrev()
user_bytes = new_suffix[::-1]

# Send forged request
response = requests.get(URL, params={'user': user_bytes, 'hmac': new_hash})
```

## Flag
```
247CTF{6ba8d812XXXXXXXXXXXXXXXX73a9f335}
```

## Lessons Learned

1. **Merkle-Damgård Construction**: SHA-256's structure allows extending hashes
2. **Length Extension Attack**: Compute `H(secret || known || padding || extension)` from `H(secret || known)`
3. **Why Real HMAC is Secure**: HMAC uses `H(key XOR opad || H(key XOR ipad || message))` which prevents this attack
4. **The strrev() Factor**: We reverse our crafted suffix to account for PHP's string reversal

## Prevention
- Use proper HMAC: `hash_hmac('sha256', $user, $flag)`
- This is immune to length extension because of the nested hash structure
