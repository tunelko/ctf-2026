# Cosmic Components

| Field       | Value                        |
|-------------|------------------------------|
| Platform    | UniVsThreats 2026 Quals      |
| Category    | web                          |
| Difficulty  | Medium                       |

## Description

> Online shop for cosmic components. Buy all products to reach the highest tier and unlock the flag.

## TL;DR

Vendor coupon stacking vulnerability: the coupons `NEWCUSTOMER10` and `SPACESALE15` can be applied repeatedly to the same cart, reducing the total to nearly zero. This allows purchasing all products with the starting balance, unlocking the flag.

## Vulnerability Identified

### Type: Business logic flaw — Unbounded coupon stacking (CWE-840)

The `/cart/coupon` endpoint does not enforce a limit on coupon applications per cart. Each call to apply `NEWCUSTOMER10` or `SPACESALE15` further reduces the cart total by a percentage. After ~60 iterations of stacking both coupons, the total drops below BBD 1.00, making any product affordable.

## Solution Process

### Step 1: Register and login

Create a new account and authenticate to get a session.

### Step 2: Buy each product with stacked coupons

For each product in tier order (Quantum RAM → Neutrino SSD → Ion Voucher → Ion Processor → Nvidia GPU → Dark Matter PSU):
1. Add product to cart
2. Apply `NEWCUSTOMER10` and `SPACESALE15` coupons ~60 times each
3. Cart total drops to near-zero
4. Checkout — product purchased, tier progresses

### Step 3: Retrieve flag

After buying all products and reaching the highest tier, `GET /flag` returns the flag.

## Execution

```bash
python3 solve.py http://target:port
```

## Flag

```
UVT{...}  # Extracted at runtime by solve.py
```

## Key Lessons

- Always test coupon/discount endpoints for stacking — percentage-based discounts applied iteratively converge to zero
- Business logic flaws in e-commerce checkout flows are a common CTF web category
