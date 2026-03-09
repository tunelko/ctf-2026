#!/usr/bin/env python3
"""
Challenge: Deoxyribonucleic acid — upCTF 2026
Category:  misc (DNA data storage encoding)
Flag:      upCTF{DnA_IsCh3pear_Th3n_R4M}

Goldman et al. (2013) encoding: each DNA base encodes a trit (0/1/2)
relative to the previous base. 6 trits per byte → ASCII.
"""

dna = "ACTCTACGAGTCTACAGAGTCGTCGTATCAGTCTCACGTGAGCGAGTATACAGTGTCGAGCGTGCGACTCGCTACAGAGTCGCTGTAGCACGAGTCTAGTGTGTCGATCGAGTGTAGTCTGTCGTCGTCGCTGTAGCACGAGTATAGTCTGTCGTAGTAGCAGTATGATAGAGCA"

# Goldman rotating substitution: (prev_base, curr_base) → trit
#           | 0 | 1 | 2
#  ---------|---|---|---
#     A     | C | G | T
#     C     | G | T | A
#     G     | T | A | C
#     T     | A | C | G
decode_table = {}
for prev, row in [('A', 'CGT'), ('C', 'GTA'), ('G', 'TAC'), ('T', 'ACG')]:
    for trit, base in enumerate(row):
        decode_table[(prev, base)] = trit

# DNA → trits
trits = [decode_table[(dna[i-1], dna[i])] for i in range(1, len(dna))]

# 6 trits → 1 byte (3^6 = 729 > 256)
flag = ''
for i in range(0, len(trits) - 5, 6):
    val = 0
    for j in range(6):
        val = val * 3 + trits[i + j]
    flag += chr(val)

print(f"FLAG: {flag}")
