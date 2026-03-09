# vibedns — upCTF 2026

**Category:** Misc (DNSSEC / Crypto)
**Flag:** `upCTF{ev3n_wh3n_1ts_crypto_1ts_alw4ys_Dn5_yHZiigxyf06e2681}`

## TL;DR

Custom DNSSEC signer seeds Python's `random` PRNG with the public inception timestamp to generate the ECDSA private key. Extract inception from any RRSIG, regenerate the key, forge a valid RRSIG for `flag.xstf.pt.`, submit to `/verify` endpoint.

---

## Analysis

### Architecture

```
dns_server.py     — Multiplexed TCP: DNS-over-TCP + HTTP API
dnssec_signer.py  — Signs zone with ECDSA P-256 (Algorithm 13)
```

- The server exposes `POST /verify` which validates an RRSIG for `flag.xstf.pt.` and returns the flag if valid
- DNS queries return records signed with RRSIG

### Vulnerability: Deterministic PRNG (CWE-330)

```python
# dnssec_signer.py, line 149
def generate_zsk(inception_timestamp):
    random.seed(inception_timestamp)                          # ← PUBLIC SEED
    key_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    private_int = int.from_bytes(key_bytes, "big") % (P256_ORDER - 1) + 1
    private_key = ec.derive_private_key(private_int, ec.SECP256R1(), ...)
```

The `inception_timestamp` is a public field included in every RRSIG that the server returns. Anyone can:

1. Query an RRSIG → obtain the `inception_timestamp`
2. `random.seed(inception_timestamp)` → regenerate the same byte sequence
3. Derive the identical ECDSA private key
4. Sign any arbitrary record

### Verification Endpoint

```python
# POST /verify — accepts: name, type, ttl, rdata, sig
# name MUST be "flag.xstf.pt."
# Uses inception/expiration/key_tag from the server's zone_data
# Verifies sig against the DNSKEY public key
```

The server reconstructs the `rrsig_header` with its own `inception`/`expiration`/`key_tag`, so we only need to provide `rtype`, `ttl`, `rdata`, and a valid signature.

---

## Exploit

### Flow

```
1. DNS Query DNSKEY → parse RRSIG → inception_timestamp = 1772988888
2. random.seed(1772988888) → regenerate private_key → key_tag = 41670 ✓
3. Sign: flag.xstf.pt. TXT "pwned" ttl=3600
4. POST /verify → RRSIG_VERIFIED → flag
```

### solve.py (key excerpt)

```python
# Step 1: DNS query → inception
resp_data = dns_query_tcp(HOST, PORT, "xstf.pt.", 48)  # DNSKEY
inception_ts = parse_rrsig(resp_data)["inception"]       # 1772988888

# Step 2: Recover private key
private_key, public_key, key_tag = generate_zsk(inception_ts)
# key_tag matches server's → confirms correct key recovery

# Step 3: Forge RRSIG for flag.xstf.pt.
rrsig_header = build_rrsig_header("TXT", 3600, inception_ts, expiration_ts, key_tag, "xstf.pt.")
rrset_wire = build_rrset_wire("flag.xstf.pt.", "TXT", 3600, ["pwned"])
signature = sign_rrset(private_key, rrsig_header, rrset_wire)

# Step 4: Submit
requests.post(f"http://{HOST}:{PORT}/verify", data={
    "name": "flag.xstf.pt.", "type": "TXT", "ttl": "3600",
    "rdata": "pwned", "sig": base64.b64encode(signature).decode()
})
# → {"status": "RRSIG_VERIFIED", "flag": "upCTF{...}"}
```

```
$ python3 solve.py 46.225.117.62 30019
[+] Inception: 1772988888
[+] Recovered key tag: 41670
[+] Key tag matches!
[+] Response (200):
{"status": "RRSIG_VERIFIED", "flag": "upCTF{ev3n_wh3n_1ts_crypto_1ts_alw4ys_Dn5_yHZiigxyf06e2681}"}
```

---

## Key Lessons

1. **Never seed PRNG with public data for key generation**: `random.seed(inception_timestamp)` makes the key fully deterministic from public information
2. **Python `random` is not cryptographic**: Mersenne Twister is designed for statistical simulations, not security. Use `secrets` or `os.urandom()` for key material
3. **DNSSEC inception/expiration are public**: they're transmitted in every RRSIG record — using them as entropy source is equivalent to publishing the key
4. **"Vibe coding" crypto = disaster**: the challenge title hints at the problem — cargo-culting DNSSEC implementation without understanding key generation security

## References

- [RFC 6605 — ECDSA for DNSSEC](https://tools.ietf.org/html/rfc6605)
- [RFC 4034 — DNSSEC Resource Records](https://tools.ietf.org/html/rfc4034)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
