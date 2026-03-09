#!/usr/bin/env python3
"""
dnssec_signer.py — Custom DNSSEC Zone Signer for xstf.pt

Signs all zone records using ECDSA P-256 (Algorithm 13) as per RFC 6605.
Generates Zone Signing Key (ZSK) at startup and produces RRSIG records
for every RRset in the zone.

The signed zone is exported to zone_signed.json for the DNS server.

Dependencies: cryptography
"""

import random
import struct
import time
import json
import base64
import hashlib
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# ============================================================
# Configuration
# ============================================================

ZONE_NAME = "xstf.pt."
ZONE_FILE_OUT = "zone_signed.json"

# RRSIG timing: signatures are valid for 30 days
SIGNATURE_VALIDITY_DAYS = 30

# DNSSEC Algorithm 13 = ECDSAP256SHA256 (RFC 6605)
ALGORITHM = 13

# ============================================================
# Zone Definition
# ============================================================

ZONE_RECORDS = [
    # Serial is a placeholder — sign_zone() replaces it with YYYYMMDDvv derived from inception_ts
    {"name": "xstf.pt.",      "type": "SOA",  "ttl": 86400,
     "rdata": "ns1.xstf.pt. admin.xstf.pt. 0000000000 3600 900 604800 86400"},

    {"name": "xstf.pt.",      "type": "NS",   "ttl": 86400,
     "rdata": "ns1.xstf.pt."},

    {"name": "xstf.pt.",      "type": "NS",   "ttl": 86400,
     "rdata": "ns2.xstf.pt."},

    {"name": "ns1.xstf.pt.",  "type": "A",    "ttl": 3600,
     "rdata": "10.0.13.1"},

    {"name": "ns2.xstf.pt.",  "type": "A",    "ttl": 3600,
     "rdata": "10.0.13.2"},

    {"name": "www.xstf.pt.",  "type": "A",    "ttl": 3600,
     "rdata": "10.0.13.10"},

    {"name": "mail.xstf.pt.", "type": "A",    "ttl": 3600,
     "rdata": "10.0.13.20"},

    {"name": "xstf.pt.",      "type": "MX",   "ttl": 3600,
     "rdata": "10 mail.xstf.pt."},

   
    {"name": "flag.xstf.pt.", "type": "TXT",  "ttl": 3600,
     "rdata": "upCTF{REDACTED}"},
]

# ============================================================
# DNSSEC Wire Format Helpers
# ============================================================

def dns_name_to_wire(name):
    """Encode a domain name in DNS wire format (RFC 1035 Section 3.1)."""
    wire = b""
    for label in name.rstrip(".").split("."):
        wire += bytes([len(label)]) + label.lower().encode()
    wire += b"\x00"
    return wire


def rtype_to_int(rtype):
    """Convert record type string to IANA type number."""
    TYPE_MAP = {
        "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15,
        "TXT": 16, "AAAA": 28, "RRSIG": 46, "DNSKEY": 48,
    }
    return TYPE_MAP.get(rtype.upper(), 0)


def rdata_to_wire(rtype, rdata):
    """Encode rdata in DNS wire format."""
    if rtype == "A":
        parts = rdata.split(".")
        return bytes([int(p) for p in parts])
    elif rtype == "TXT":
        encoded = rdata.encode()
        result = b""
        for i in range(0, len(encoded), 255):
            chunk = encoded[i:i+255]
            result += bytes([len(chunk)]) + chunk
        return result
    elif rtype == "NS":
        return dns_name_to_wire(rdata)
    elif rtype == "MX":
        parts = rdata.split(None, 1)
        return struct.pack("!H", int(parts[0])) + dns_name_to_wire(parts[1])
    elif rtype == "SOA":
        parts = rdata.split()
        wire = dns_name_to_wire(parts[0])  # mname
        wire += dns_name_to_wire(parts[1])  # rname
        wire += struct.pack("!IIIII", *[int(p) for p in parts[2:7]])
        return wire
    else:
        return rdata.encode()


def datetime_to_dnssec_timestamp(ts):
    """Convert Unix timestamp to DNSSEC timestamp format (YYYYMMDDHHmmSS)."""
    t = time.gmtime(ts)
    return time.strftime("%Y%m%d%H%M%S", t)


def dnssec_timestamp_to_unix(ts_str):
    """Convert DNSSEC timestamp string to Unix timestamp."""
    t = time.strptime(ts_str, "%Y%m%d%H%M%S")
    return int(time.mktime(t) - time.timezone)


# ============================================================
# Key Generation
# ============================================================

# Curve order for P-256
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def generate_zsk(inception_timestamp):
    """
    Generate a Zone Signing Key (ECDSA P-256).
    Returns:
        (private_key, public_key, key_tag) tuple
    """
    random.seed(inception_timestamp)

    key_bytes = bytes([random.randint(0, 255) for _ in range(32)])

    private_int = int.from_bytes(key_bytes, "big") % (P256_ORDER - 1) + 1

    private_key = ec.derive_private_key(private_int, ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # Compute DNSKEY key tag (RFC 4034, Appendix B)
    dnskey_rdata = build_dnskey_rdata(public_key)
    key_tag = compute_key_tag(dnskey_rdata)

    return private_key, public_key, key_tag


def build_dnskey_rdata(public_key):
    """
    Build DNSKEY RDATA in wire format (RFC 4034 Section 2.1).

    Format: Flags (2) | Protocol (1) | Algorithm (1) | Public Key (variable)
    """
    flags = 256     
    protocol = 3 
    algorithm = ALGORITHM

    # ECDSA P-256 public key: raw x || y coordinates (64 bytes)
    pub_uncompressed = public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )
    pub_raw = pub_uncompressed[1:]  # Strip 0x04 prefix

    rdata = struct.pack("!HBB", flags, protocol, algorithm) + pub_raw
    return rdata


def compute_key_tag(dnskey_rdata):
    """
    Compute DNSKEY key tag per RFC 4034, Appendix B.

    Simple checksum over the DNSKEY RDATA used to identify
    which key signed an RRSIG.
    """
    ac = 0
    for i, byte in enumerate(dnskey_rdata):
        if i % 2 == 0:
            ac += byte << 8
        else:
            ac += byte
    return ((ac & 0xFFFF) + (ac >> 16)) & 0xFFFF


# ============================================================
# RRSIG Generation
# ============================================================

def build_rrsig_header(rtype, ttl, inception, expiration, key_tag, signer_name):
    """
    Build the RRSIG RDATA header (everything except the signature).

    RFC 4034 Section 3.1:
        Type Covered (2) | Algorithm (1) | Labels (1) | Original TTL (4) |
        Signature Expiration (4) | Signature Inception (4) | Key Tag (2) |
        Signer's Name (variable)
    """
    type_covered = rtype_to_int(rtype)
    labels = len(signer_name.rstrip(".").split("."))

    header = struct.pack("!HBBI", type_covered, ALGORITHM, labels, ttl)
    header += struct.pack("!I", expiration)
    header += struct.pack("!I", inception)
    header += struct.pack("!H", key_tag)
    header += dns_name_to_wire(signer_name)

    return header


def build_rrset_wire(name, rtype, ttl, rdata_list):
    """
    Build the canonical wire format of an RRset for signing.

    RFC 4034 Section 6.3: Each RR is encoded as:
        name | type | class | ttl | rdlength | rdata
    sorted by rdata in canonical order.
    """
    wire = b""
    for rdata in sorted(rdata_list):
        rdata_wire = rdata_to_wire(rtype, rdata)
        wire += dns_name_to_wire(name)
        wire += struct.pack("!HHI", rtype_to_int(rtype), 1, ttl)  # class = IN (1)
        wire += struct.pack("!H", len(rdata_wire))
        wire += rdata_wire
    return wire


def sign_rrset(private_key, rrsig_header, rrset_wire):
    """
    Sign an RRset.

    The signed data is: RRSIG_RDATA_HEADER || RRSET_WIRE
    The signature is ECDSA P-256 with SHA-256.

    Returns the raw signature bytes (r || s, 64 bytes) per RFC 6605.
    """
    data_to_sign = rrsig_header + rrset_wire

    # Sign with ECDSA
    der_signature = private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))

    # Convert DER signature to raw (r || s) format per RFC 6605 Section 4
    r, s = decode_dss_signature(der_signature)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    return raw_sig


# ============================================================
# Main: Sign the Zone
# ============================================================

def sign_zone(inception_ts=None):
    """Sign all zone records and produce a signed zone file."""

    if inception_ts is None:
        inception_ts = int(time.time())

    expiration_ts = inception_ts + (SIGNATURE_VALIDITY_DAYS * 86400)

    print(f"[signer] Inception:  {datetime_to_dnssec_timestamp(inception_ts)} ({inception_ts})", file=sys.stderr)
    print(f"[signer] Expiration: {datetime_to_dnssec_timestamp(expiration_ts)} ({expiration_ts})", file=sys.stderr)

    # Generate ZSK
    private_key, public_key, key_tag = generate_zsk(inception_ts)
    print(f"[signer] ZSK key tag: {key_tag}", file=sys.stderr)

    # Build DNSKEY record
    dnskey_rdata_bytes = build_dnskey_rdata(public_key)
    dnskey_rdata_b64 = base64.b64encode(dnskey_rdata_bytes).decode()

    # SOA serial derived from inception timestamp in YYYYMMDDvv format
    soa_serial = time.strftime("%Y%m%d01", time.gmtime(inception_ts))

    # Group records by (name, type) to form RRsets
    rrsets = {}
    for rec in ZONE_RECORDS:
        key = (rec["name"], rec["type"])
        if key not in rrsets:
            rrsets[key] = {"name": rec["name"], "type": rec["type"], "ttl": rec["ttl"], "rdata_list": []}
        rdata = rec["rdata"]
        if rec["type"] == "SOA":
            parts = rdata.split()
            parts[2] = soa_serial
            rdata = " ".join(parts)
        rrsets[key]["rdata_list"].append(rdata)

    # Sign each RRset
    signed_records = []
    for (name, rtype), rrset in rrsets.items():
        rrsig_header = build_rrsig_header(
            rtype, rrset["ttl"], inception_ts, expiration_ts, key_tag, ZONE_NAME
        )
        rrset_wire = build_rrset_wire(name, rtype, rrset["ttl"], rrset["rdata_list"])
        signature = sign_rrset(private_key, rrsig_header, rrset_wire)

        rrsig_data = {
            "type_covered": rtype,
            "algorithm": ALGORITHM,
            "labels": len(name.rstrip(".").split(".")),
            "original_ttl": rrset["ttl"],
            "expiration": expiration_ts,
            "expiration_str": datetime_to_dnssec_timestamp(expiration_ts),
            "inception": inception_ts,
            "inception_str": datetime_to_dnssec_timestamp(inception_ts),
            "key_tag": key_tag,
            "signer": ZONE_NAME,
            "signature": base64.b64encode(signature).decode(),
        }

        signed_records.append({
            "name": name,
            "type": rtype,
            "ttl": rrset["ttl"],
            "rdata_list": rrset["rdata_list"],
            "rrsig": rrsig_data,
        })

        print(f"[signer]   Signed: {name} {rtype}", file=sys.stderr)

    # Also sign the DNSKEY RRset itself
    dnskey_rrset_wire = (
        dns_name_to_wire(ZONE_NAME)
        + struct.pack("!HHI", rtype_to_int("DNSKEY"), 1, 86400)
        + struct.pack("!H", len(dnskey_rdata_bytes))
        + dnskey_rdata_bytes
    )
    dnskey_rrsig_header = build_rrsig_header(
        "DNSKEY", 86400, inception_ts, expiration_ts, key_tag, ZONE_NAME
    )
    dnskey_sig = sign_rrset(private_key, dnskey_rrsig_header, dnskey_rrset_wire)

    # Build output
    output = {
        "zone": ZONE_NAME,
        "inception": inception_ts,
        "expiration": expiration_ts,
        "dnskey": {
            "name": ZONE_NAME,
            "type": "DNSKEY",
            "ttl": 86400,
            "flags": 256,
            "protocol": 3,
            "algorithm": ALGORITHM,
            "public_key": dnskey_rdata_b64,
            "key_tag": key_tag,
            "rrsig": {
                "type_covered": "DNSKEY",
                "algorithm": ALGORITHM,
                "inception": inception_ts,
                "inception_str": datetime_to_dnssec_timestamp(inception_ts),
                "expiration": expiration_ts,
                "expiration_str": datetime_to_dnssec_timestamp(expiration_ts),
                "key_tag": key_tag,
                "signer": ZONE_NAME,
                "signature": base64.b64encode(dnskey_sig).decode(),
            }
        },
        "records": signed_records,
    }

    return output


if __name__ == "__main__":
    import os

    inception = int(os.environ.get("INCEPTION_TS", int(time.time())))

    zone_data = sign_zone(inception)

    out_path = os.environ.get("ZONE_FILE_OUT", ZONE_FILE_OUT)
    with open(out_path, "w") as f:
        json.dump(zone_data, f, indent=2)

    print(f"[signer] Zone written to {out_path}", file=sys.stderr)
