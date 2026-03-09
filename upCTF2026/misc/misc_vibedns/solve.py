#!/usr/bin/env python3
"""
Challenge: vibedns — upCTF 2026
Category:  misc (DNSSEC / crypto)

Vuln: private key seeded with random.seed(inception_timestamp).
inception_timestamp is public (in every RRSIG) → recover private key → forge RRSIG.
"""

import random
import struct
import socket
import base64
import sys
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# --- Config ---
HOST = sys.argv[1] if len(sys.argv) > 1 else "46.225.117.62"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 30010

# --- Constants from dnssec_signer.py ---
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
ALGORITHM = 13
ZONE_NAME = "xstf.pt."
SIGNATURE_VALIDITY_DAYS = 30

def dns_name_to_wire(name):
    wire = b""
    for label in name.rstrip(".").split("."):
        wire += bytes([len(label)]) + label.lower().encode()
    wire += b"\x00"
    return wire

def rtype_to_int(rtype):
    TYPE_MAP = {"A":1,"NS":2,"CNAME":5,"SOA":6,"MX":15,"TXT":16,"AAAA":28,"RRSIG":46,"DNSKEY":48}
    return TYPE_MAP.get(rtype.upper(), 0)

def rdata_to_wire(rtype, rdata):
    if rtype == "A":
        return bytes([int(p) for p in rdata.split(".")])
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
        wire = dns_name_to_wire(parts[0]) + dns_name_to_wire(parts[1])
        wire += struct.pack("!IIIII", *[int(p) for p in parts[2:7]])
        return wire
    return rdata.encode()

def build_dnskey_rdata(public_key):
    flags = 256
    protocol = 3
    algorithm = ALGORITHM
    pub_uncompressed = public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    pub_raw = pub_uncompressed[1:]
    return struct.pack("!HBB", flags, protocol, algorithm) + pub_raw

def compute_key_tag(dnskey_rdata):
    ac = 0
    for i, byte in enumerate(dnskey_rdata):
        if i % 2 == 0:
            ac += byte << 8
        else:
            ac += byte
    return ((ac & 0xFFFF) + (ac >> 16)) & 0xFFFF

def generate_zsk(inception_timestamp):
    random.seed(inception_timestamp)
    key_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    private_int = int.from_bytes(key_bytes, "big") % (P256_ORDER - 1) + 1
    private_key = ec.derive_private_key(private_int, ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    dnskey_rdata = build_dnskey_rdata(public_key)
    key_tag = compute_key_tag(dnskey_rdata)
    return private_key, public_key, key_tag

def build_rrsig_header(rtype, ttl, inception, expiration, key_tag, signer_name):
    type_covered = rtype_to_int(rtype)
    labels = len(signer_name.rstrip(".").split("."))
    header = struct.pack("!HBBI", type_covered, ALGORITHM, labels, ttl)
    header += struct.pack("!I", expiration)
    header += struct.pack("!I", inception)
    header += struct.pack("!H", key_tag)
    header += dns_name_to_wire(signer_name)
    return header

def build_rrset_wire(name, rtype, ttl, rdata_list):
    wire = b""
    for rdata in sorted(rdata_list):
        rdata_wire = rdata_to_wire(rtype, rdata)
        wire += dns_name_to_wire(name)
        wire += struct.pack("!HHI", rtype_to_int(rtype), 1, ttl)
        wire += struct.pack("!H", len(rdata_wire))
        wire += rdata_wire
    return wire

def sign_rrset(private_key, rrsig_header, rrset_wire):
    data_to_sign = rrsig_header + rrset_wire
    der_signature = private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")

# =====================================================
# Step 1: DNS query to get inception from RRSIG
# =====================================================
def dns_query_tcp(host, port, qname, qtype_num):
    """Send DNS query over TCP and return raw response."""
    # Build query
    txid = 0x1337
    flags = 0x0100  # standard query, RD=1
    query = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    for label in qname.rstrip(".").split("."):
        query += bytes([len(label)]) + label.encode()
    query += b"\x00"
    query += struct.pack("!HH", qtype_num, 1)  # type, class IN

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    sock.sendall(struct.pack("!H", len(query)) + query)

    # Recv response
    length_data = sock.recv(2)
    msg_len = struct.unpack("!H", length_data)[0]
    data = b""
    while len(data) < msg_len:
        chunk = sock.recv(msg_len - len(data))
        if not chunk:
            break
        data += chunk
    sock.close()
    return data

def parse_dns_response(data):
    """Parse DNS response to extract RRSIG inception/expiration."""
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    offset = 12

    # Skip question section
    for _ in range(qdcount):
        while offset < len(data) and data[offset] != 0:
            if data[offset] & 0xC0 == 0xC0:  # compression pointer
                offset += 2
                break
            length = data[offset]
            offset += 1 + length
        else:
            offset += 1  # null terminator
        offset += 4  # qtype + qclass

    # Parse answer section
    results = []
    for _ in range(ancount):
        # Parse name (handle compression)
        if offset < len(data) and data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                length = data[offset]
                offset += 1 + length
            offset += 1

        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlength]
        offset += rdlength

        if rtype == 46:  # RRSIG
            # Parse RRSIG fields
            type_covered, algorithm, labels, orig_ttl = struct.unpack("!HBBI", rdata[:8])
            expiration, inception = struct.unpack("!II", rdata[8:16])
            key_tag = struct.unpack("!H", rdata[16:18])[0]
            results.append({
                "type": "RRSIG",
                "type_covered": type_covered,
                "algorithm": algorithm,
                "inception": inception,
                "expiration": expiration,
                "key_tag": key_tag,
            })
        else:
            results.append({"type": rtype, "rdata": rdata})

    return results

# =====================================================
# Main exploit
# =====================================================
print(f"[*] Targeting {HOST}:{PORT}")

# Step 1: Get inception timestamp via DNS query for DNSKEY
print("[*] Querying DNS for DNSKEY + RRSIG...")
resp_data = dns_query_tcp(HOST, PORT, "xstf.pt.", 48)  # DNSKEY
records = parse_dns_response(resp_data)

rrsig = None
for r in records:
    if r.get("type") == "RRSIG":
        rrsig = r
        break

if not rrsig:
    print("[-] No RRSIG found in response!")
    sys.exit(1)

inception_ts = rrsig["inception"]
expiration_ts = rrsig["expiration"]
key_tag_from_server = rrsig["key_tag"]
print(f"[+] Inception: {inception_ts}")
print(f"[+] Expiration: {expiration_ts}")
print(f"[+] Key tag: {key_tag_from_server}")

# Step 2: Recover private key
print("[*] Recovering private key from inception seed...")
private_key, public_key, key_tag = generate_zsk(inception_ts)
print(f"[+] Recovered key tag: {key_tag}")
assert key_tag == key_tag_from_server, f"Key tag mismatch: {key_tag} vs {key_tag_from_server}"
print("[+] Key tag matches!")

# Step 3: Forge RRSIG for flag.xstf.pt. TXT
name = "flag.xstf.pt."
rtype = "TXT"
ttl = 3600
rdata = "pwned"  # arbitrary TXT content

rrsig_header = build_rrsig_header(rtype, ttl, inception_ts, expiration_ts, key_tag, ZONE_NAME)
rrset_wire = build_rrset_wire(name, rtype, ttl, [rdata])
signature = sign_rrset(private_key, rrsig_header, rrset_wire)
sig_b64 = base64.b64encode(signature).decode()

print(f"[+] Forged signature: {sig_b64[:40]}...")

# Step 4: Submit to /verify
print("[*] Submitting forged RRSIG to /verify...")
url = f"http://{HOST}:{PORT}/verify"
payload = {
    "name": name,
    "type": rtype,
    "ttl": str(ttl),
    "rdata": rdata,
    "sig": sig_b64,
}

resp = requests.post(url, data=payload, timeout=10)
print(f"[+] Response ({resp.status_code}):")
print(resp.text)
