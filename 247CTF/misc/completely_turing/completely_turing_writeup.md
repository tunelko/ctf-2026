# completely_turing - 247CTF Writeup

## Challenge Description
> We encoded the flag in a terse, but Turing complete programming language. Can you identify the valid characters required to extract the flag?

## Analysis

The challenge provides a Brainfuck program (`completely_turing`) that contains an encrypted flag. The program asks for "key" inputs at each index position and uses those to decrypt the flag.

### Understanding the Encryption

By analyzing the Brainfuck source code, we can identify the encryption pattern:

1. **Value Storage**: The program uses multiplication patterns to store encrypted values:
   ```brainfuck
   +N[-<+M>]<+P
   ```
   This computes the value `N * M + P`

2. **Extracting Encrypted Values**: Using regex to find all multiplication patterns:
   ```python
   pattern = r'(\+{1,})\[-<(\+{1,})>\]<(\+*)'
   ```

3. **Filtering**: Values > 40 are the encrypted flag characters (ASCII printable range)

### Discovering the Key Pattern

By reverse-engineering the first 7 characters (known prefix `247CTF{`):

| Position | Encrypted | Expected | Key | Digit |
|----------|-----------|----------|-----|-------|
| 0 | 128 | '2' (50) | 78 | 8 |
| 1 | 127 | '4' (52) | 75 | 5 |
| 2 | 133 | '7' (55) | 78 | 8 |
| 3 | 142 | 'C' (67) | 75 | 5 |
| 4 | 162 | 'T' (84) | 78 | 8 |
| 5 | 145 | 'F' (70) | 75 | 5 |
| 6 | 201 | '{' (123) | 78 | 8 |

**Pattern discovered**: Key = 70 + digit, where digit **alternates between 8 and 5**

The "valid characters required to extract the flag" are: **8** and **5**, alternating.

### Decryption Formula

```
plaintext[i] = encrypted[i] - (70 + digit)
where digit = 8 if i is even, 5 if i is odd
```

## Solution

```python
import re

with open('completely_turing', 'r') as f:
    code = f.read()

pattern = r'(\+{1,})\[-<(\+{1,})>\]<(\+*)'
matches = re.findall(pattern, code)

encrypted = [len(m)*len(i)+len(e) for m,i,e in matches if len(m)*len(i)+len(e) > 40][:40]

flag = ''
for i, enc in enumerate(encrypted):
    key = 70 + (8 if i % 2 == 0 else 5)
    flag += chr(enc - key)

print(flag)
```

## Flag

```
247CTF{dccaXXXXXXXXXXXXXXXXX22ead17a}
```

## Key Insight

The challenge asks to "identify the valid characters" - these are the key digits 8 and 5 that must be entered alternately for each position to decrypt the flag. Static analysis of the Brainfuck multiplication patterns reveals the encrypted values, allowing direct decryption without running the program.
