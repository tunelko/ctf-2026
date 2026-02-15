#!/usr/bin/env python3
"""
Deep Fried Data - Final: do not stop at fake flags, continue decoding
"""

import gzip
import bz2
import lzma
import zlib
import base64
import subprocess
import tempfile
import os
import re

def identify_and_decompress(data):
    """Identify the format and decompress"""

    # gzip
    if data[:2] == b'\x1f\x8b':
        try:
            return gzip.decompress(data), 'gzip'
        except Exception:
            pass

    # bzip2
    if data[:2] == b'BZ':
        try:
            return bz2.decompress(data), 'bzip2'
        except Exception:
            pass

    # xz
    if data[:6] == b'\xfd7zXZ\x00':
        try:
            return lzma.decompress(data), 'xz'
        except Exception:
            pass

    # lzma
    if data[:3] == b'\x5d\x00\x00':
        try:
            return lzma.decompress(data), 'lzma'
        except Exception:
            pass

    # zlib
    if len(data) > 1 and data[0] == 0x78 and data[1] in (0x01, 0x5e, 0x9c, 0xda):
        try:
            return zlib.decompress(data), 'zlib'
        except Exception:
            pass

    # zstd
    if data[:4] == b'\x28\xb5\x2f\xfd':
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.zst') as f:
                f.write(data)
                f.flush()
                r = subprocess.run(['zstd', '-d', '-c', f.name], capture_output=True)
                os.unlink(f.name)
                if r.returncode == 0:
                    return r.stdout, 'zstd'
        except Exception:
            pass

    # lz4
    if data[:4] == b'\x04\x22\x4d\x18':
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.lz4') as f:
                f.write(data)
                f.flush()
                r = subprocess.run(['lz4', '-d', '-c', f.name], capture_output=True)
                os.unlink(f.name)
                if r.returncode == 0:
                    return r.stdout, 'lz4'
        except Exception:
            pass

    # zip
    if data[:2] == b'PK':
        try:
            import zipfile
            import io
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()
                return zf.read(names[0]), f'zip({names[0]})'
        except Exception:
            pass

    # tar
    if len(data) > 262 and data[257:262] == b'ustar':
        try:
            import tarfile
            import io
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                member = tf.getmembers()[0]
                f = tf.extractfile(member)
                if f:
                    return f.read(), f'tar({member.name})'
        except Exception:
            pass

    # Text-based
    try:
        text = data.decode('ascii').strip()
    except (UnicodeDecodeError, ValueError):
        text = None

    if text:
        # Check for fake flag with data following
        if 'REAL_DATA_FOLLOWS:' in text:
            idx = text.index('REAL_DATA_FOLLOWS:')
            remaining = text[idx + len('REAL_DATA_FOLLOWS:'):].strip()
            if remaining:
                return remaining.encode(), 'extract-real-data'

        # ASCII85
        if text.startswith('<~'):
            try:
                end = text.find('~>')
                if end == -1:
                    a85_data = text[2:]
                else:
                    a85_data = text[2:end]
                decoded = base64.a85decode(a85_data)
                if len(decoded) > 0:
                    return decoded, 'ascii85'
            except Exception:
                pass

        charset = set(text.replace('\n', '').replace('\r', ''))

        # hex
        hex_chars = set('0123456789abcdefABCDEF')
        if charset <= hex_chars and len(text) > 4:
            clean = text.replace('\n', '').replace('\r', '').replace(' ', '')
            if len(clean) % 2 == 0:
                try:
                    return bytes.fromhex(clean), 'hex'
                except Exception:
                    pass

        # base32
        b32_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=')
        if charset <= b32_chars and len(text) > 4:
            try:
                padded = text.replace('\n', '').replace('\r', '')
                pad_needed = (8 - len(padded) % 8) % 8
                padded += '=' * pad_needed
                decoded = base64.b32decode(padded)
                if len(decoded) > 0:
                    return decoded, 'base32'
            except Exception:
                pass

        # base64
        b64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        if charset <= b64_chars and len(text) > 4:
            try:
                decoded = base64.b64decode(text)
                if len(decoded) > 0:
                    return decoded, 'base64'
            except Exception:
                pass

        # base85 RFC
        try:
            decoded = base64.b85decode(text)
            if len(decoded) > 0:
                return decoded, 'base85'
        except Exception:
            pass

    # brotli
    try:
        import brotli
        result = brotli.decompress(data)
        return result, 'brotli'
    except Exception:
        pass

    # Raw deflate
    try:
        result = zlib.decompress(data, -zlib.MAX_WBITS)
        return result, 'deflate-raw'
    except Exception:
        pass

    # Zlib force
    try:
        result = zlib.decompress(data)
        return result, 'zlib-force'
    except Exception:
        pass

    return None, None

# Read
with open('/home/ubuntu/0xfun/ctf/challenges/misc/notes.txt', 'rb') as f:
    data = f.read()

print(f"[*] Start: {len(data)} bytes")

layer = 0
flags_found = []

while layer < 2000:
    result, method = identify_and_decompress(data)

    if result is None:
        print(f"\n[!] Stuck at layer {layer}")
        print(f"    Size: {len(data)} bytes")
        if len(data) >= 20:
            print(f"    Magic: {data[:20].hex()}")
        try:
            text = data.decode('utf-8')
            print(f"    Text: {text[:500]}")
        except:
            print(f"    Hex: {data[:200].hex()}")
        break

    layer += 1
    data = result

    if layer <= 20 or layer % 50 == 0 or method == 'extract-real-data' or len(data) < 1000:
        magic = data[:4].hex() if len(data) >= 4 else data.hex()
        print(f"  Layer {layer:3d}: {method:20s} -> {len(data):>10d} bytes | {magic}")

    # Check for flags
    try:
        text = data.decode('utf-8')
        matches = re.findall(r'0xfun\{[^}]+\}', text)
        for flag in matches:
            if flag not in flags_found:
                flags_found.append(flag)
                print(f"\n  [FLAG layer {layer}] {flag}")
        if len(text) < 200 and '0xfun{' not in text and 'REAL_DATA' not in text:
            print(f"    Text: {text.strip()}")
    except:
        pass

print(f"\n[*] Total layers: {layer}")
print(f"[*] Flags found: {len(flags_found)}")
for f in flags_found:
    print(f"    {f}")
