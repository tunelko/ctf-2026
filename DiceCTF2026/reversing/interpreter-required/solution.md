# interpreter-required — DiceCTF 2026 (Rev)

## TL;DR

Custom **Church-encoded lambda calculus interpreter** with Chinese/Wenyan-style syntax. The `flag_riddle.txt` program computes the flag character-by-character using Church numerals, but running it directly OOMs because Church arithmetic on large numbers creates exponentially many thunks. The solve is to reverse the language grammar, parse the program statically, and evaluate the arithmetic natively in Python.

**Flag:** `dice{y0u_int3rpret3d_Th3_CJK_gr4mMaR_succ3ssfully}`

---

## Description

> I found this riddle in some ancient language, but I'm not sure what it means... (don't interpret the puzzle, it will OOM your computer)

**Files:** `interpreter` (stripped ELF 64-bit, statically linked), `flag_riddle.txt` (73 KB, UTF-8 Chinese text)

---

## Analysis

### Step 1 — Initial Recon

```
$ file interpreter
ELF 64-bit LSB executable, x86-64, statically linked, stripped

$ file flag_riddle.txt
Unicode text, UTF-8 text

$ ./interpreter
Expected filename as first arg

$ timeout 10 ./interpreter flag_riddle.txt
===
```

Running the interpreter on the riddle outputs `===` and seems to hang (would OOM). The description confirms: don't run it naively.

### Step 2 — Reverse Engineering the Interpreter

The binary is a custom **untyped lambda calculus** interpreter. Each expression node is 24 bytes:

| Offset | Type 0 (Variable) | Type 1 (Lambda) | Type 2 (Application) |
|--------|-------------------|-----------------|----------------------|
| 0      | type = 0          | type = 1        | type = 2             |
| 8      | name ref          | param name      | function ptr         |
| 16     | —                 | body expr       | argument ptr         |

Key functions identified via Ghidra/r2:

| Address    | Function                                     |
|------------|----------------------------------------------|
| `0x40254f` | `main` — reads file, evaluates, prints flag  |
| `0x40238b` | File reader — tokenizer + expression builder  |
| `0x4022de` | Parse lambda (`以`)                           |
| `0x402419` | Parse application (`为`)                      |
| `0x402191` | Beta-reduction (one-step evaluation)          |
| `0x402127` | Substitution `[var := expr]`                  |
| `0x402494` | Church numeral → integer (count applications) |
| `0x401c02` | Output character (integer → UTF-8 char)       |
| `0x401b08` | CJK character filter (strips non-CJK)         |

The binary first strips all non-CJK characters (comments, English text, punctuation, whitespace) from the input. Only CJK Unified Ideographs and related ranges survive. Then it parses and evaluates the remaining lambda calculus program.

### Step 3 — Language Grammar

The language uses five core syntactic characters:

| Character | Unicode  | Role                             |
|-----------|----------|----------------------------------|
| **以**    | U+4EE5   | Lambda keyword (λ)               |
| **而**    | U+800C   | Dot separator (λx **.**  body)   |
| **为**    | U+4E3A   | Application / definition body    |
| **矣**    | U+77E3   | End delimiter (closing paren)    |
| **于**    | U+4E8E   | Argument separator (grouping)    |

Grammar:
```
以<params>而为<body>矣          → lambda abstraction: λparams.body
为<f><arg>[于<arg>]*矣          → application: f(arg1)(arg2)...
X<expr>                          → definition: X = expr
```

Example from the riddle preamble:
```
真以矛盾而为矛矣    →  真 = λ矛.λ盾.矛     (Church TRUE: select first)
假以矛盾而为盾矣    →  假 = λ矛.λ盾.盾     (Church FALSE: select second)
正以人而为人矣       →  正 = λ人.人           (identity function)
```

### Step 4 — Church Encodings in the Program

The program defines a full Church-encoded arithmetic library:

#### Booleans & Identity
| Name | Definition              | Meaning         |
|------|-------------------------|-----------------|
| 真   | λa.λb.a                | TRUE            |
| 假   | λa.λb.b                | FALSE           |
| 正   | λx.x                   | Identity        |
| 可   | λp.λt.λf.p(t)(f)       | IF/conditional  |

#### Church Numerals
| Name | Value | Definition          |
|------|-------|---------------------|
| 無   | 0     | λf.λx.x            |
| 甲   | 1     | λf.λx.f(x)         |
| 乙   | 2     | λf.λx.f(f(x))      |
| 丙   | 3     | λf.λx.f(f(f(x)))   |
| 丁   | 4     | λf.λx.f⁴(x)        |

#### Arithmetic
| Name | Operation       | Church encoding                        |
|------|-----------------|----------------------------------------|
| 生   | Successor       | λn.λf.λx.f(n(f)(x))                   |
| 合   | Addition        | λm.λn.m(succ)(n)                       |
| 次   | Multiplication  | λm.λn.λf.m(n(f))                       |
| 销   | Subtraction     | λm.λn.n(pred)(m) (floors at 0)         |
| 幂   | Exponentiation  | λm.λn.n(m)                              |
| 阶   | Factorial       | Via Y-combinator (步(步))               |
| 分   | Integer division| Complex Church division                  |

#### Data Structures
| Name | Operation      | Definition               |
|------|----------------|--------------------------|
| 双   | Pair           | λa.λb.λf.f(a)(b)        |
| 有   | Cons (prepend) | pair(TRUE, x)            |
| 无   | Nil            | pair(FALSE, id)          |
| 在/本 | Car (head)    | p(TRUE)                  |
| 用/末 | Cdr (tail)    | p(FALSE)                 |

#### Binary Number Literals
Numbers are encoded as binary Church numerals between `朝` (start) and `暮` (end), with bits in **LSB-first** order:
- **春** = bit 0
- **秋** = bit 1

Example: `朝秋春秋秋秋秋暮` → bits `[1,0,1,1,1,1]` LSB → `0b111101` = **61** = `'='`

The `早` (early) function folds over these bits: `state = (0, 1) → for bit: (val + bit*scale, scale*2)`.

### Step 5 — Flag Structure

The program builds a linked list called `旗` (flag) where each element is a Church numeral representing a character code. The main function iterates this list, reduces each Church numeral to an integer (by counting applications), and outputs the corresponding Unicode character.

The first ~50 characters use direct binary literals (e.g., `㐀为朝春秋春秋暮` = 10 = newline).
Characters 50+ are computed via complex arithmetic chains like:

```
㐴为阶㐳矣        → factorial(㐳)
㐷为合㐴㐶矣      → 㐴 + 㐶
㐹为销㐷㐸矣      → 㐷 - 㐸
㑘为次㑐㑗矣      → 㑐 × 㑗
㑍为分㑉㑌矣      → 㑉 ÷ 㑌
```

This is why it OOMs: Church-encoding `factorial(10)` = 3628800 means a lambda term with 3.6 million nested applications. Exponentiation and division compound this astronomically.

### Step 6 — The Solve

Instead of evaluating Church-encoded lambda terms, we:
1. Strip non-CJK characters (matching the interpreter's filter)
2. Parse binary literals `X为朝<bits>暮` into native integers
3. Parse arithmetic operations `X为<op>YZ矣` into expression trees
4. Evaluate natively in Python (factorial, pow, etc.)
5. Extract the flag list from `于双为有X矣` patterns
6. Convert each integer to a character

---

## Vulnerability / Technique

- **CWE-N/A** — Pure reversing challenge
- **Technique:** Static analysis of a custom esoteric language interpreter. Recognize that Church-encoded arithmetic is computationally intractable at scale, and bypass evaluation by parsing the program structure and evaluating with native arithmetic.

---

## Exploit / Solver

```python
#!/usr/bin/env python3
"""
DiceCTF 2026 - interpreter-required (Rev)
Solver: Parse the Wenyan lambda calculus program statically
and evaluate arithmetic natively to extract the flag.
"""

import re, math, sys

def solve(filepath):
    with open(filepath, 'r') as f:
        text = f.read()

    # Strip non-CJK characters (matching the binary's filter)
    clean = ''
    for c in text:
        cp = ord(c)
        if (0x4E00 <= cp <= 0x9FFF or
            0x3200 <= cp <= 0x4DBF or
            0x2E80 <= cp <= 0x2FDF or
            0x2FF0 <= cp <= 0x303F or
            0x31C0 <= cp <= 0x31EF or
            0xF900 <= cp <= 0xFAFF):
            clean += c

    # Parse binary literals: X为朝<bits>暮 → LSB-first
    # 春 = 0, 秋 = 1
    all_vals = {}
    for m in re.finditer(r'([\u3400-\u9fff])为朝([春秋]+)暮', clean):
        name = m.group(1)
        if name not in all_vals:
            bits = [0 if b == '春' else 1 for b in m.group(2)]
            all_vals[name] = sum(b * (2**i) for i, b in enumerate(bits))

    # Parse operation definitions
    ops = {}
    for m in re.finditer(r'([\u3400-\u9fff])为阶([\u3400-\u9fff])矣', clean):
        name = m.group(1)
        if name not in all_vals and name not in ops:
            ops[name] = ('阶', m.group(2))  # factorial

    for op in ['销', '幂', '分', '合', '次']:
        for m in re.finditer(
            r'([\u3400-\u9fff])为' + op + r'([\u3400-\u9fff])([\u3400-\u9fff])矣',
            clean
        ):
            name = m.group(1)
            if name not in all_vals and name not in ops:
                ops[name] = (op, m.group(2), m.group(3))

    # Recursive evaluator with memoization
    memo = {}
    def ev(name):
        if name in memo:
            return memo[name]
        if name in all_vals:
            memo[name] = all_vals[name]
            return all_vals[name]
        if name not in ops:
            return None
        op = ops[name]
        try:
            if op[0] == '阶':
                a = ev(op[1])
                if a is None or a > 1000: return None
                result = math.factorial(a)
            elif op[0] == '合':  # add
                a, b = ev(op[1]), ev(op[2])
                if None in (a, b): return None
                result = a + b
            elif op[0] == '次':  # multiply
                a, b = ev(op[1]), ev(op[2])
                if None in (a, b): return None
                result = a * b
            elif op[0] == '幂':  # exponentiate
                a, b = ev(op[1]), ev(op[2])
                if None in (a, b): return None
                result = a ** b
            elif op[0] == '销':  # subtract (floor 0)
                a, b = ev(op[1]), ev(op[2])
                if None in (a, b): return None
                result = max(0, a - b)
            elif op[0] == '分':  # integer division
                a, b = ev(op[1]), ev(op[2])
                if None in (a, b) or b == 0: return None
                result = a // b
            else:
                return None
            memo[name] = result
            return result
        except:
            return None

    # Extract flag linked list: 于双为有X矣 pattern
    flag_chars = [
        m.group(1) for m in re.finditer(r'于双为有([\u3400-\u9fff])矣', clean)
    ]

    # Evaluate each character and print
    output = ''.join(chr(ev(fc)) if ev(fc) else '?' for fc in flag_chars)
    print(output)

    flag_match = re.search(r'dice\{[^}]+\}', output)
    if flag_match:
        print(f"\nFLAG: {flag_match.group()}")

if __name__ == '__main__':
    solve(sys.argv[1] if len(sys.argv) > 1 else 'flag_riddle.txt')
```

```
$ python3 solve.py flag_riddle.txt
=== INTERPRETER REQUIRED ===
Calculating flag...


Thanks for playing!

旗子：
dice{y0u_int3rpret3d_Th3_CJK_gr4mMaR_succ3ssfully}
这是λ之道也！

FLAG: dice{y0u_int3rpret3d_Th3_CJK_gr4mMaR_succ3ssfully}
```

---

## Approaches Considered / Discarded

1. **Run the interpreter directly** — OOMs as warned. Church-encoded `factorial(10)` = 3.6M nested applications; exponentiation makes it exponentially worse.
2. **Patch the interpreter** to use native integers — Would require significant binary patching of the evaluation engine; too complex vs. writing a custom parser.
3. **Wenyan-lang (文言)** — Initially suspected this was the Wenyan programming language, but the grammar is custom (pure lambda calculus, not Wenyan's imperative style).

---

## Key Lessons

- **Church encoding is computationally explosive** — Even small numbers become massive lambda terms. The challenge exploits this: the program is semantically correct but practically impossible to evaluate naively.
- **Custom esoteric languages** — When given a custom interpreter, reverse the grammar before trying to execute. Pattern recognition on the input file (repeated structures, delimiters) can shortcut full decompilation.
- **LSB-first binary encoding** — The `朝...暮` number literals use least-significant-bit first, which is unusual and easy to misread as MSB.
- **Static evaluation bypasses dynamic complexity** — The program is pure (no side effects, no I/O during computation), so every expression can be statically analyzed and evaluated with native arithmetic.

---

## Flag

```
dice{y0u_int3rpret3d_Th3_CJK_gr4mMaR_succ3ssfully}
```

---

## References

- [Church encoding (Wikipedia)](https://en.wikipedia.org/wiki/Church_encoding)
- [Lambda calculus](https://en.wikipedia.org/wiki/Lambda_calculus)
- [Wenyan programming language](https://wy-lang.org/) — similar aesthetic, different language
- [千字文 (Thousand Character Classic)](https://en.wikipedia.org/wiki/Thousand_Character_Classic) — source of some variable names in the `分` (division) function
