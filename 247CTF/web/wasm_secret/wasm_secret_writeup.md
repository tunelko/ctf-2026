# WASM Secret - 247CTF

## Challenge Information

- **Platform**: 247CTF
- **Category**: Reversing / Crypto
- **Difficulty**: Medium
- **Flag**: `247CTF{167d16d4XXXXXXXXXXXXXXXX23ff0238}`

## Description

> A secret flag is safely hidden away within client side scripts. We were told JavaScript is an insecure medium for secret storage, so we decided to use C++ instead.

## Provided Files

```
flag.html  (3.5 KB)  - Web interface
flag.js    (36 KB)   - Emscripten code (WASM loader)
flag.wasm  (44 KB)   - Compiled WebAssembly module
```

---

## Initial Analysis

### 1. HTML Review

```html
<script>
function getFlag(){
  var valid_flag = false;
  var flag = document.getElementById('flag').value;
  try {
    valid_flag = Module.CompareFlag(flag);
  } catch (err){
    error.textContent = err.message;
    return false;
  }
  if (valid_flag){
    alert(flag);
  } else {
    error.textContent = "Invalid flag!";
  }
  return false;
}
</script>
<script src="flag.js"></script>
```

The page calls `Module.CompareFlag(input)` which is an exported function from the WASM module.

### 2. WASM Decompilation

```bash
wasm2wat flag.wasm > flag.wat
```

The resulting WAT file contains the disassembled code and the data section.

### 3. Data Extraction

Searching for strings in the WASM data section:

```bash
grep -o '\$2b\$12\$[A-Za-z0-9./]\{53\}' flag.wat
```

**40 bcrypt hashes** are found:

```
$2b$12$uAfq9EI1EoIC316VgA3azeOyogkKzG4zz2kF8M.l.D4h4nT4WsidK
$2b$12$NmhDm/LZzjanlv6xuHCsVe8JJNlvEb3uYUEQ03abPIlCuTE6qtrT.
$2b$12$8OhK6ZPoSuBujRxR3pz4g.vp6LvTqJe/NJZZHTHtOPkdIbDb1GDKS
$2b$12$PhFiPd28yDeXdZaJfUDjTOiAUQtpBJ2AjD5pFIG7CtUXQtWECGpre
$2b$12$DfQJicmUWZQ0EVGKxdQEN.yCj3s4o6GyMraqt514d3DRkAqH8PYq6
$2b$12$JikQohCsuFN6DO7q9ZHCTeHuzL3/Hb3diMYJsUGgAI4AH64x9jtyO
$2b$12$4C2jJ0QxCKdqyrBTIhqEGeeq1IMOZJs7DllwqtMWbp.rM7BPsbDwG
$2b$12$FI45z3VbyCC4Bb5rVJsLb./Od6aSnT8tHIPkwmZCgGNNrXwpJqkO6
$2b$12$tFkj/QdzBVsk8XjjjH91eefYY/lx6YX/4lnB9T/GKSIvpmx7mEEG2
$2b$12$Il.BDj/qxIkgROEZN4/Te.QJawuPW18MHU1hVQzNIC9SW7H.Mo9.2
$2b$12$3UOGifrFe0iGGh4sSWx1JeB919LDApovzwbYIQqniIFVE3/mgEFkW
$2b$12$5voYYJHxGJVy3ITneNhk/.XbcfOKDDnMHiS2CTri0ncFQ/jUgND.e
$2b$12$cDvS2AqrJ72gvUP5wSnjSOqdsFIKcsGI863NxXgdedYzMV0YzOZmW
$2b$12$pIcJfpN7L0SGQtA/4bcX.ewqrSkeUzCeq4mrjHCzhwQKB2LTc4tJe
$2b$12$4xjImCcvXpgG.WFwjlryEONm4gFy3/O2VSCsrL1lX38f0XDPKc6Hm
$2b$12$gIWlY5GubfJ1kIhMEO9GnuTbalD8aPc6ECdNIq.4Vjx6S38nKLG8S
$2b$12$9UpsAlXYVpPw4B93u2WBm.Ve0JMqdkQ0wxvuAPqnXmtzjmvXm0hea
$2b$12$QqTL8meoLdWMnipKwuRoC.d9ei6TU2ev1Ggu0VsC2gLGMfF7QWOPi
$2b$12$8M.Z95IrSP64adu2LiOhzO4vhtmfjBx45Pp.FJsq4Tqe/t5GaPeA2
$2b$12$GNWfLovpvpMcoK89QdZzt.u8XibRtwo0aFFnUSBcqs0SjocL6hgVS
$2b$12$mLzTYglkEg3iqusfz8lOOuH548ezA.mgfr8pYI7cd3ozU8aPJBhAC
$2b$12$6GTg.qAyDUQorM1BwcIXRe7Ab.L3ZXqJhI0xg2G.OtCVf5W1BH7zu
$2b$12$Nxd1aKxcgV4s51dN5nc2puAtG8J6asT8vcvB0kfWhcfYp868nza7.
$2b$12$Z2/4n8JEXI19ZFL7A4ojEOiSbfAeV3KZj5Nc0.Uu6sXG6KHvtPCLi
$2b$12$AEiJfo2eTPnTCU.NL2jJeOifcw/TOAZaOLjMAPKEdfJmgdQy/WoYC
$2b$12$8pA4oDi3uovODvOuf2GrteqltIOhDUH/AI07H1NrvCoA5AvL9vKJe
$2b$12$Kke80penOJ8l7/EBoDZCWufdwdWju/Twb6.9DSm498.I922qNBfBK
$2b$12$xOcqWzPSMN3VgbsmEmZbYe98NBK1Qxpp6fAZNYCEiU/Lw5vsbIOz.
$2b$12$OnXeQsiQyBpIZzciVGSkUuBwcr62OoirL8Ebb9QczH7AAFdIsrbxi
$2b$12$3c8V9ss5ATsQkkz0ZUg2T.x0qCBszvuetJPX.vm9XPgsGBwhedfhy
$2b$12$xVrrb1qPs3mHX2kp6vo10e8zsUqDxXxlmptJnFBT/5YVDeSGAJsty
$2b$12$BA5vnPd.oxWN4BEn6PybEeXgWYrX02k9rHXLnDAiDedUilCuiv2jy
$2b$12$7p6s4NoKXsjqD/0wnuO2b.2ux70dPNcN5wBYccuzz8vm1ZZ9iPPLu
$2b$12$oXuFS3O5Td3knq2gRyf5XOhwj1.IYOWQ9fSvGY05YU0MwizIm18Ru
$2b$12$l3wvb/fiYbkzoqWv1.ulMuQPTn6xP67D0/YkjNzwJi1bK30qJAZWu
$2b$12$3eFpVZJh6TfrnbE.hdfitu8UiqLei7u2vEjFPecu6O5FqNqyOYOs.
$2b$12$XtrkQGAyvRcIdCtW4AK9/.9oSlP2rAwE.KNk5f2sKuyhhDNzIAvzC
$2b$12$zrsIpC4WnPVjcCRODlRXT.IDPIZwBEP2VwTv.q5/DIfCpdD44zoam
$2b$12$Lr3UiwLPab6yEw.TERhNAu1/qlQelYuqmF/Wcg3UtrzslAzrf3/di
$2b$12$RtpdIcXU8hH8pnDGQHCupu5l2mw872X6SFamb20w9A.sieVEk7Xba
```

**Observation**: 40 hashes = 40 characters = length of `247CTF{32-hex-chars}`

---

## Pattern Discovery

### Initial Hypothesis: One Hash per Character

First attempt: assume each hash corresponds to a single character.

```python
import bcrypt

charset = "0123456789abcdefCTF{}247"
h0 = b"$2b$12$uAfq9EI1EoIC316VgA3azeOyogkKzG4zz2kF8M.l.D4h4nT4WsidK"

for c in charset:
    if bcrypt.checkpw(c.encode(), h0):
        print(f"Hash 0 = '{c}'")
        break
```

**Result**: Only hash[0] = '2' works. The rest find no match.

### Testing with Expected Characters

```python
# If the flag is 247CTF{...}, the first 7 chars should be "247CTF{"
expected = "247CTF{"
for i, c in enumerate(expected):
    result = bcrypt.checkpw(c.encode(), hashes[i])
    print(f"Pos {i}: '{c}' -> {result}")
```

**Result**:
```
Pos 0: '2' -> True
Pos 1: '4' -> False   # Should be True!
Pos 2: '7' -> False
...
```

### Correct Hypothesis: Cumulative Prefixes

```python
prefixes = ["2", "24", "247", "247C", "247CT", "247CTF", "247CTF{"]
for i, p in enumerate(prefixes):
    result = bcrypt.checkpw(p.encode(), hashes[i])
    print(f"Pos {i}: '{p}' -> {result}")
```

**Result**:
```
Pos 0: '2' -> True
Pos 1: '24' -> True
Pos 2: '247' -> True
Pos 3: '247C' -> True
Pos 4: '247CT' -> True
Pos 5: '247CTF' -> True
Pos 6: '247CTF{' -> True
```

**Pattern discovered**: Each hash corresponds to a **cumulative prefix** of the flag:
- hash[0] = bcrypt(flag[0:1])
- hash[1] = bcrypt(flag[0:2])
- hash[2] = bcrypt(flag[0:3])
- ...
- hash[39] = bcrypt(flag[0:40])

---

## Exploitation

With the known pattern, the flag can be cracked character by character:
1. We know the current prefix (initially empty)
2. We try each possible character: prefix + c
3. If bcrypt matches, we append c to the prefix
4. We repeat for all 40 hashes

---

## Solution Script

```python
#!/usr/bin/env python3
"""
WASM Secret - 247CTF Solver
Cracks the flag using cumulative bcrypt prefixes
"""

import bcrypt

hashes = [
    b"$2b$12$uAfq9EI1EoIC316VgA3azeOyogkKzG4zz2kF8M.l.D4h4nT4WsidK",
    b"$2b$12$NmhDm/LZzjanlv6xuHCsVe8JJNlvEb3uYUEQ03abPIlCuTE6qtrT.",
    b"$2b$12$8OhK6ZPoSuBujRxR3pz4g.vp6LvTqJe/NJZZHTHtOPkdIbDb1GDKS",
    b"$2b$12$PhFiPd28yDeXdZaJfUDjTOiAUQtpBJ2AjD5pFIG7CtUXQtWECGpre",
    b"$2b$12$DfQJicmUWZQ0EVGKxdQEN.yCj3s4o6GyMraqt514d3DRkAqH8PYq6",
    b"$2b$12$JikQohCsuFN6DO7q9ZHCTeHuzL3/Hb3diMYJsUGgAI4AH64x9jtyO",
    b"$2b$12$4C2jJ0QxCKdqyrBTIhqEGeeq1IMOZJs7DllwqtMWbp.rM7BPsbDwG",
    b"$2b$12$FI45z3VbyCC4Bb5rVJsLb./Od6aSnT8tHIPkwmZCgGNNrXwpJqkO6",
    b"$2b$12$tFkj/QdzBVsk8XjjjH91eefYY/lx6YX/4lnB9T/GKSIvpmx7mEEG2",
    b"$2b$12$Il.BDj/qxIkgROEZN4/Te.QJawuPW18MHU1hVQzNIC9SW7H.Mo9.2",
    b"$2b$12$3UOGifrFe0iGGh4sSWx1JeB919LDApovzwbYIQqniIFVE3/mgEFkW",
    b"$2b$12$5voYYJHxGJVy3ITneNhk/.XbcfOKDDnMHiS2CTri0ncFQ/jUgND.e",
    b"$2b$12$cDvS2AqrJ72gvUP5wSnjSOqdsFIKcsGI863NxXgdedYzMV0YzOZmW",
    b"$2b$12$pIcJfpN7L0SGQtA/4bcX.ewqrSkeUzCeq4mrjHCzhwQKB2LTc4tJe",
    b"$2b$12$4xjImCcvXpgG.WFwjlryEONm4gFy3/O2VSCsrL1lX38f0XDPKc6Hm",
    b"$2b$12$gIWlY5GubfJ1kIhMEO9GnuTbalD8aPc6ECdNIq.4Vjx6S38nKLG8S",
    b"$2b$12$9UpsAlXYVpPw4B93u2WBm.Ve0JMqdkQ0wxvuAPqnXmtzjmvXm0hea",
    b"$2b$12$QqTL8meoLdWMnipKwuRoC.d9ei6TU2ev1Ggu0VsC2gLGMfF7QWOPi",
    b"$2b$12$8M.Z95IrSP64adu2LiOhzO4vhtmfjBx45Pp.FJsq4Tqe/t5GaPeA2",
    b"$2b$12$GNWfLovpvpMcoK89QdZzt.u8XibRtwo0aFFnUSBcqs0SjocL6hgVS",
    b"$2b$12$mLzTYglkEg3iqusfz8lOOuH548ezA.mgfr8pYI7cd3ozU8aPJBhAC",
    b"$2b$12$6GTg.qAyDUQorM1BwcIXRe7Ab.L3ZXqJhI0xg2G.OtCVf5W1BH7zu",
    b"$2b$12$Nxd1aKxcgV4s51dN5nc2puAtG8J6asT8vcvB0kfWhcfYp868nza7.",
    b"$2b$12$Z2/4n8JEXI19ZFL7A4ojEOiSbfAeV3KZj5Nc0.Uu6sXG6KHvtPCLi",
    b"$2b$12$AEiJfo2eTPnTCU.NL2jJeOifcw/TOAZaOLjMAPKEdfJmgdQy/WoYC",
    b"$2b$12$8pA4oDi3uovODvOuf2GrteqltIOhDUH/AI07H1NrvCoA5AvL9vKJe",
    b"$2b$12$Kke80penOJ8l7/EBoDZCWufdwdWju/Twb6.9DSm498.I922qNBfBK",
    b"$2b$12$xOcqWzPSMN3VgbsmEmZbYe98NBK1Qxpp6fAZNYCEiU/Lw5vsbIOz.",
    b"$2b$12$OnXeQsiQyBpIZzciVGSkUuBwcr62OoirL8Ebb9QczH7AAFdIsrbxi",
    b"$2b$12$3c8V9ss5ATsQkkz0ZUg2T.x0qCBszvuetJPX.vm9XPgsGBwhedfhy",
    b"$2b$12$xVrrb1qPs3mHX2kp6vo10e8zsUqDxXxlmptJnFBT/5YVDeSGAJsty",
    b"$2b$12$BA5vnPd.oxWN4BEn6PybEeXgWYrX02k9rHXLnDAiDedUilCuiv2jy",
    b"$2b$12$7p6s4NoKXsjqD/0wnuO2b.2ux70dPNcN5wBYccuzz8vm1ZZ9iPPLu",
    b"$2b$12$oXuFS3O5Td3knq2gRyf5XOhwj1.IYOWQ9fSvGY05YU0MwizIm18Ru",
    b"$2b$12$l3wvb/fiYbkzoqWv1.ulMuQPTn6xP67D0/YkjNzwJi1bK30qJAZWu",
    b"$2b$12$3eFpVZJh6TfrnbE.hdfitu8UiqLei7u2vEjFPecu6O5FqNqyOYOs.",
    b"$2b$12$XtrkQGAyvRcIdCtW4AK9/.9oSlP2rAwE.KNk5f2sKuyhhDNzIAvzC",
    b"$2b$12$zrsIpC4WnPVjcCRODlRXT.IDPIZwBEP2VwTv.q5/DIfCpdD44zoam",
    b"$2b$12$Lr3UiwLPab6yEw.TERhNAu1/qlQelYuqmF/Wcg3UtrzslAzrf3/di",
    b"$2b$12$RtpdIcXU8hH8pnDGQHCupu5l2mw872X6SFamb20w9A.sieVEk7Xba",
]

# Possible characters in the flag: 247CTF{} + hex
charset = "0123456789abcdefCTF{}247"

def crack():
    flag = ""

    print("Cracking flag using cumulative prefixes...")
    print("=" * 50)

    for i, h in enumerate(hashes):
        found = False
        for c in charset:
            candidate = flag + c
            if bcrypt.checkpw(candidate.encode(), h):
                flag = candidate
                print(f"[{i:02d}] {flag}")
                found = True
                break

        if not found:
            print(f"[{i:02d}] ERROR: Character not found after '{flag}'")
            return None

    print("=" * 50)
    return flag

if __name__ == "__main__":
    result = crack()
    if result:
        print(f"\nFLAG: {result}")
```

---

## Execution

```
$ python3 solve.py
Cracking flag using cumulative prefixes...
==================================================
[00] 2
[01] 24
[02] 247
[03] 247C
[04] 247CT
[05] 247CTF
[06] 247CTF{
[07] 247CTF{X
[08] 247CTF{XX
...
[38] 247CTF{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
[39] 247CTF{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
==================================================

FLAG: 247CTF{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```

Execution time: ~2-3 minutes (bcrypt is intentionally slow)

---

## Lessons Learned

1. **WebAssembly is not secure for secrets**: Data embedded in WASM can be easily extracted using `wasm2wat` or similar tools.

2. **bcrypt with prefixes**: Although bcrypt is resistant to brute force, using cumulative prefixes allows cracking character by character (only ~24 attempts per position instead of 24^40).

3. **Pattern analysis**: When one approach fails (hash per character), try variations (prefixes, suffixes, position+character, etc.).

---

## Tools Used

- `wasm2wat` - WASM to WAT decompiler (WebAssembly Text Format)
- `grep` - Hash extraction from the binary
- Python + `bcrypt` - Hash cracking

---

## References

- [WebAssembly Text Format](https://webassembly.github.io/spec/core/text/index.html)
- [bcrypt](https://en.wikipedia.org/wiki/Bcrypt)
- [WABT (WebAssembly Binary Toolkit)](https://github.com/WebAssembly/wabt)