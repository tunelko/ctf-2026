# Network Nuance — VishwaCTF 2026 (Forensics)

## TL;DR

ICMP sequence numbers encode the flag as `ord(char) + 100`.

## Solution

```python
import re
data = open('network_log.txt').read()
seqs = [int(x) for x in re.findall(r'SeqNum=(\d+)', data)]
print(''.join(chr(s - 100) for s in seqs))
```

## Flag

```
VishwaCTF{N3tw0rk_P4ck3t_H1dd3n_VH}
```
