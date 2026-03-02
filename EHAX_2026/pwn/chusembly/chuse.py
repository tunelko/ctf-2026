#!/usr/bin/env python3
"""Helper to run Chusembly code and extract output"""
import requests
import sys
import re

URL = "http://chall.ehax.in:6969/run"

def run(code):
    r = requests.post(URL, data={"code": code})
    # Extract between <pre> and </pre>
    m = re.search(r'<pre>(.*?)</pre>', r.text, re.DOTALL)
    if m:
        return m.group(1).strip()
    return "(no output)"

if __name__ == "__main__":
    if len(sys.argv) > 1:
        code = open(sys.argv[1]).read()
    else:
        code = sys.stdin.read()
    print(run(code))
