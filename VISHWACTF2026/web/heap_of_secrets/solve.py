import requests

data = requests.get("https://heap.vishwactf.com/api/init").json()
flag = ''.join(chr(b ^ data['session_seed']) for b in data['trace_vector'])
print(flag)
