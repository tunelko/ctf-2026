# Not My Modulus - Writeup

## Challenge Description
We are trying to decrypt a packet capture taken on our internal network. We know you can decrypt the data using the correct private key, but we simply have too many. Can you identify the correct key?

## Files
- `encrypted.pcap` - TLS encrypted packet capture
- `keys.tar.gz` - Archive containing 1000 private keys

## Analysis

### The Problem
We have a TLS-encrypted pcap and 1000 candidate private keys. We need to find the one that matches the server's certificate.

### Key Insight: RSA Modulus Matching
In RSA, the public key and private key share the same **modulus**. The server's certificate contains the public key, so we can:
1. Extract the certificate's modulus from the pcap
2. Find the private key with the matching modulus

## Solution

### Step 1: Extract Certificate from PCAP
```bash
tshark -r encrypted.pcap -Y "tls.handshake.certificate" -T fields -e tls.handshake.certificate | head -1 | xxd -r -p > cert.der
```

### Step 2: Get Certificate Modulus
```bash
openssl x509 -inform DER -in cert.der -noout -modulus
# Modulus=C1170184E4F93017A84C069647093967266624C3BFC78B82756CC4733459ACAE...
```

### Step 3: Find Matching Private Key
```bash
TARGET=$(openssl x509 -inform DER -in cert.der -noout -modulus | cut -d= -f2)

for key in keys/*.key; do
    MOD=$(openssl rsa -in "$key" -noout -modulus 2>/dev/null | cut -d= -f2)
    if [ "$MOD" = "$TARGET" ]; then
        echo "FOUND: $key"
        break
    fi
done
# FOUND: keys/518dfdb269ef17a932a893a63630644c.key
```

### Step 4: Decrypt TLS Traffic
```bash
tshark -r encrypted.pcap -o "tls.keys_list:127.0.0.1,443,http,correct_key.pem" -Y "http" -T fields -e http.file_data | xxd -r -p
# flag=247CTF{3693df4dXXXXXXXXXXXXXXXX94c9e9c3}Closing connection
```

## Flag
```
247CTF{3693df4dXXXXXXXXXXXXXXXX94c9e9c3}
```

## Lessons Learned

1. **RSA Key Pairing**: Public and private keys share the same modulus (n = p × q)
2. **TLS Decryption**: With the server's private key, we can decrypt the pre-master secret and derive session keys
3. **Certificate Extraction**: TLS handshake contains the server certificate in plaintext

## Tools Used
- `tshark` - Extract certificate and decrypt TLS
- `openssl` - Parse certificates and keys, extract modulus
- `xxd` - Hex conversion
