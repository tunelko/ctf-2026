# c47chm31fy0uc4n  

**Category:** Forensics

**Difficulty:** Hard

**CTF/Platform:** Pragyan CTF 2026

**Description:**  
A Linux server is suspected to have been compromised. A memory dump has been provided for analysis. Using only the provided memory dump, determine:

- the session key exfiltrated by the malicious process  
- the epoch timestamp used during the exfiltration  
- the IP address the program exfiltrated sensitive data to  
- the ephemeral source port used by the attacker during remote access  

A Linux server is suspected to have been compromised. During the incident window, administrators observed suspicious user activity and abnormal process behavior, but no malicious binaries were recovered from disk.

You are provided with a full memory dump of the system taken shortly after the incident. Initial triage suggests that an attacker may have:

- Accessed the system remotely  
- Executed a malicious userspace program  
- Exfiltrated sensitive session data before disappearing  

Your task is to analyze the memory dump and reconstruct what happened.

**Objectives**  
Using only the provided memory dump, determine:

- The session key exfiltrated by the malicious process  
- The epoch timestamp used during the exfiltration  
- The IP address the program exfiltrated sensitive data to  
- The ephemeral source port used by the attacker during remote access  

You must correlate process activity, memory artifacts, and session metadata to arrive at your answer.

**Flag format:**: p_ctf{<session_key>:<epoch>:<exfiltration_ip>:<ephemeral_remote_execution_port>}

**Download evidence:** https://drive.google.com/file/d/1LOlj1vNeGKZccLOtMeGhAZi2UR0whuJJ/view?usp=sharing
---

## Overview

We are given a 4GB LiME memory dump (`memdump.fin`) from a compromised Ubuntu 20.04 server. The objective is to reconstruct 4 pieces of information from the attacker's activity:

1. The **session key** exfiltrated by the malicious process
2. The **epoch timestamp** used during the exfiltration
3. The **exfiltration IP** address
4. The **ephemeral source port** used by the attacker's SSH session

Flag format: `p_ctf{<session_key>:<epoch>:<exfiltration_ip>:<ephemeral_remote_execution_port>}`

---

## Step 1: Identify the Kernel Version

First, we identify the kernel version from the memory dump to set up the correct Volatility3 symbol table.

```bash
strings memdump.fin | grep -i "linux version" | head -5
```

```
Linux version 5.15.0-139-generic (buildd@lcy02-amd64-112) (gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #149~20.04.1-Ubuntu SMP Mon Dec 23 14:22:42 UTC 2024
```

Kernel: **Linux 5.15.0-139-generic** on **Ubuntu 20.04 HWE** (Hardware Enablement stack).

---

## Step 2: Generate the Volatility3 Symbol Table (ISF)

Volatility3 for Linux requires an ISF (Intermediate Symbol Format) file matching the exact kernel version. This is generated from the kernel's DWARF debug symbols.

### 2.1 Download the kernel debug symbols (ddeb)

```bash
wget "https://launchpad.net/ubuntu/+archive/primary/+files/linux-image-unsigned-5.15.0-139-generic-dbgsym_5.15.0-139.149~20.04.1_amd64.ddeb" \
  -O kernel-dbgsym.ddeb
```

### 2.2 Extract the vmlinux with debug info

```bash
mkdir -p ddeb-extract
dpkg-deb -x kernel-dbgsym.ddeb ddeb-extract/
ls ddeb-extract/usr/lib/debug/boot/
# vmlinux-5.15.0-139-generic (1.1GB with DWARF)
```

### 2.3 Generate the ISF with dwarf2json

```bash
dwarf2json linux \
  --elf ddeb-extract/usr/lib/debug/boot/vmlinux-5.15.0-139-generic \
  > volatility3/volatility3/symbols/linux/ubuntu-5.15.0-139-generic.json
```

This produces a ~47MB JSON symbol table. Volatility3 auto-discovers it from the `symbols/linux/` directory.

### 2.4 Verify Volatility works

```bash
python3 volatility3/vol.py -f memdump.fin linux.pslist
```

```
PID    PPID   COMM
1      0      systemd
...
1019   1      sshd
1526   1019   sshd
1669   1526   sshd
1677   1669   bash
1699   1019   sshd
1753   1699   sshd
1754   1753   bash
1770   1677   msg_sync --sess     <-- SUSPICIOUS
1782   1754   sudo
1783   1782   insmod
```

Success. The process `msg_sync --sess` (PID 1770) immediately stands out as suspicious.

---

## Step 3: Map the Process Tree

```bash
python3 volatility3/vol.py -f memdump.fin linux.pstree
```

```
* sshd [1019]                          # Main SSH daemon
** sshd [1526]                         # Session 1 (attacker)
*** sshd [1669]                        # Privilege separation child
**** bash [1677]                       # Attacker's shell
***** msg_sync --sess [1770]           # MALICIOUS PROCESS
** sshd [1699]                         # Session 2 (same attacker)
*** sshd [1753]                        # Privilege separation child
**** bash [1754]                       # Second shell
***** sudo [1782]                      # Running LiME
****** insmod [1783]                   # Loading LiME kernel module
```

Two SSH sessions are active:
- **Session 1** (bash[1677]): Running the malicious `msg_sync` binary
- **Session 2** (bash[1754]): Taking a memory dump with LiME via `insmod`

---

## Step 4: Identify the Ephemeral SSH Port (Objective 4)

```bash
python3 volatility3/vol.py -f memdump.fin linux.sockstat
```

Filtering for the SSH connections:

```
PID   Protocol  Local                    Remote                     State
1526  TCP       192.168.153.130:22  -->  192.168.153.1:57540        ESTABLISHED
1669  TCP       192.168.153.130:22  -->  192.168.153.1:57540        ESTABLISHED
1699  TCP       192.168.153.130:22  -->  192.168.153.1:57547        ESTABLISHED
1753  TCP       192.168.153.130:22  -->  192.168.153.1:57547        ESTABLISHED
```

- **Session 1** (sshd[1526] -> bash[1677] -> msg_sync[1770]): Source port **57540**
- **Session 2** (sshd[1699] -> bash[1754] -> insmod[1783]): Source port 57547

The attacker's SSH session that launched msg_sync used ephemeral port **57540**.

PID 1770 (msg_sync) has **no active network sockets** -- the exfiltration connection was already closed by the time the memory dump was taken.

---

## Step 5: Recover Bash History

```bash
python3 volatility3/vol.py -f memdump.fin linux.bash
```

### Session 1 - bash[1677] (289 commands recovered)

Key commands in chronological order:

```bash
# Setup development tools
sudo apt update
sudo apt install -y build-essential gcc git ssh curl make

# Clone LiME for memory acquisition
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src && make
mv lime-5.15.0-139-generic.ko lime.ko

# Work on the malicious binary
mkdir work && cd work/
mv msg_sync.c work/msg_sync.c
cat msg_sync.c

# Multiple compilation attempts
gcc msg_sync.c -o msg_sync -O0 -g -pthread -fno-stack-protector -fno-pie -no-pie
gcc msg_sync.c -o msg_sync -g -O0 -fno-stack-protector -no-pie -lpthread

# Final compilation with full RELRO
gcc msg_sync.c -o msg_sync -O0 -g -pthread -fno-stack-protector -fno-pie -no-pie -Wl,-z,now

# Deploy the binary
sudo mv msg_sync /usr/local/bin/msg_sync

# Execute the malicious process
cd /usr/local/bin
./msg_sync                    # 2026-01-31 10:04:57 UTC

# Inspect running instances
ps aux | grep msg_sync
strings /proc/2327/environ
strings /proc/2284/environ

# Multiple memory dumps sent to forensics lab
scp memdump.fin sunlab@10.1.54.102:~/forensics/
```

### Session 2 - bash[1754] (LiME memory dump session)

```bash
cd LiME/src/
sudo insmod lime.ko path=/home/yash/work/memdump.fin format=lime
```

The timestamps from bash history show:
- `#1769853867` (10:04:27 UTC) - Start of current session activity
- `#1769853883` (10:04:43 UTC) - Session 2 starts
- Commands at 10:04:51-10:04:57 - msg_sync execution
- 10:05:03-10:06:07 - LiME dump taken (while msg_sync is running)

---

## Step 6: Analyze msg_sync Memory Layout

```bash
python3 volatility3/vol.py -f memdump.fin linux.proc.Maps --pid 1770
```

```
PID   Process          Start            End              Flags  File Path
1770  msg_sync --sess  0x400000         0x401000         r--    /usr/local/bin/msg_sync
1770  msg_sync --sess  0x401000         0x402000         r-x    /usr/local/bin/msg_sync
1770  msg_sync --sess  0x402000         0x403000         r--    /usr/local/bin/msg_sync
1770  msg_sync --sess  0x403000         0x404000         r--    /usr/local/bin/msg_sync
1770  msg_sync --sess  0x404000         0x406000         rw-    /usr/local/bin/msg_sync
1770  msg_sync --sess  0x2c670000       0x2c691000       rw-    [heap]
1770  msg_sync --sess  0x7f47ff202000   0x7f47ffa05000   rw-    Anonymous Mapping (pthread stack)
1770  msg_sync --sess  0x7f47ffc57000   0x7f47ffc58000   rwx    Anonymous Mapping   <-- RWX!
1770  msg_sync --sess  0x7fff720a9000   0x7fff720ca000   rw-    [stack]
```

Key observations:
- Binary at `/usr/local/bin/msg_sync` (compiled with `-fno-pie -no-pie`, loaded at 0x400000)
- **[heap]** region at `0x2c670000-0x2c691000`
- **RWX anonymous mapping** at `0x7f47ffc57000-0x7f47ffc58000` - This is highly suspicious: a page with read+write+execute permissions suggests runtime code generation or exploitation
- Large pthread stack (~8MB) indicating threaded operation

The combination of an active **heap** and an **RWX** mapping is the key hint for the session key.

---

## Step 7: Extract Session Key, Epoch, and Exfiltration IP (Objectives 1-3)

### 7.1 Search for the malicious process output in memory

```bash
strings memdump.fin | grep "SYNC.*FLAG"
```

```
SYNC FLAG{heap_and_rwx_never_lie} 1769853900 10.13.37.7
SYNC FLAG{heap_and_rwx_never_lie} 1769853900 10.13.37.7
```

Found twice in the memory dump. This is the output of the msg_sync process.

### 7.2 Confirm the format string in the binary

```bash
strings memdump.fin | grep "SYNC %"
```

```
SYNC %s %ld %s
```

The binary uses format: `SYNC <session_key> <epoch> <exfil_ip>`

### 7.3 Extract additional context from the binary

```bash
strings memdump.fin | grep -E "msg_sync.*session|SESSION_KEY"
```

```
msg_sync --session=FLAG{heap_and_rwx_never_lie}
SESSION_KEY
```

The session key `FLAG{heap_and_rwx_never_lie}` is passed as a command-line argument and also referenced via a `SESSION_KEY` environment variable.

### 7.4 Confirm the exfiltration IP

```bash
strings memdump.fin | grep "10\.13\.37"
```

```
10.13.37.7
```

This IP does not appear in the sockstat output (connection already closed), but is embedded in the binary and its output.

### 7.5 Verify the epoch timestamp

The epoch `1769853900` converts to:

```
2026-01-31 10:05:00 UTC
```

This aligns perfectly with the bash history timeline:
- 10:04:57 UTC: `./msg_sync` executed
- 10:05:00 UTC: msg_sync produces SYNC output (3 seconds after launch)
- 10:05:03 UTC: Second session navigates to LiME directory for memory dump

---

## Step 8: Understanding the Session Key

The session key `heap_and_rwx_never_lie` is a direct reference to the forensic artifacts visible in the process memory maps:

| Artifact | Address | Evidence |
|----------|---------|----------|
| **heap** | `0x2c670000-0x2c691000` | Standard heap allocation (rw-) |
| **rwx** | `0x7f47ffc57000-0x7f47ffc58000` | Suspicious RWX anonymous page |

The message is: "the heap and RWX mappings never lie" -- they are the forensic indicators that reveal the malicious activity. An RWX anonymous mapping is a classic indicator of:
- Shellcode execution
- JIT-compiled code
- Runtime code injection

Combined with the heap activity, these memory regions are what a forensic analyst should look for when hunting malicious processes.

---

## Solution Summary

```
                    192.168.153.1
                    (Attacker)
                         |
                    SSH (port 57540)
                         |
                         v
              +----- 192.168.153.130 -----+
              |    Ubuntu 20.04 Server    |
              |                           |
              |  sshd[1526]               |
              |    -> bash[1677]          |
              |      -> msg_sync[1770]    |
              |           |               |
              |           | SYNC output:  |
              |           | session_key + |
              |           | epoch +       |
              |           | exfil IP      |
              |           |               |
              |           v               |
              |      10.13.37.7           |
              |    (Exfil destination)     |
              +---------------------------+
```

| Component | Value | Source |
|-----------|-------|--------|
| Session key | `heap_and_rwx_never_lie` | Memory strings: `SYNC FLAG{heap_and_rwx_never_lie} 1769853900 10.13.37.7` |
| Epoch | `1769853900` | Same SYNC output (2026-01-31 10:05:00 UTC) |
| Exfiltration IP | `10.13.37.7` | Same SYNC output |
| Ephemeral SSH port | `57540` | `linux.sockstat`: 192.168.153.1:**57540** -> sshd[1526] -> bash[1677] -> msg_sync[1770] |

---

## Tools Used

- **Volatility3 2.7.0** with custom ISF generated via `dwarf2json`
  - `linux.pslist` - Process listing
  - `linux.pstree` - Process tree hierarchy
  - `linux.sockstat` - Network socket enumeration
  - `linux.bash` - Bash history recovery
  - `linux.proc.Maps` - Process memory map analysis
- **strings** + **grep** - Raw memory string extraction
- **dwarf2json** - ISF generation from kernel debug symbols (ddeb)

## Flag

```
p_ctf{heap_and_rwx_never_lie:1769853900:10.13.37.7:57540}
```
