#!/usr/bin/env python3
"""
Let's avoid doing math - DawgCTF 2026
Compute FPR and FNR per class from malware classification validation log.
120 samples, 3 classes: minor, medium, major (growing order of importance).
Format: single leading zero, no trailing zeros, comma separated.
"""
import re
from collections import defaultdict

LOG = "files/threat_depth_analysis.log"

with open(LOG) as f:
    text = f.read()

samples = []
for m in re.finditer(r'Known Threat Depth:\s*(\w+).*?Detected Threat Depth:\s*(\w+)', text, re.DOTALL):
    samples.append((m.group(1), m.group(2)))

# Confusion matrix
classes = ['minor', 'medium', 'major']  # growing importance
matrix = defaultdict(lambda: defaultdict(int))
for known, detected in samples:
    matrix[known][detected] += 1

n = len(samples)
vals = []
for c in classes:
    TP = matrix[c][c]
    FN = sum(matrix[c][d] for d in classes if d != c)
    FP = sum(matrix[k][c] for k in classes if k != c)
    TN = n - TP - FN - FP
    fpr = FP / (FP + TN)
    fnr = FN / (FN + TP)
    # Format: no trailing zeros, single leading zero
    for v in [fpr, fnr]:
        s = f"{v:.10f}".rstrip('0').rstrip('.')
        if s.startswith('.'): s = '0' + s
        vals.append(s)

flag = ','.join(vals)
print(f"[+] FLAG: DawgCTF{{{flag}}}")
