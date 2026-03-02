# Power Traces

**Category:** FORENSICS
**Flag:** `EH4X{792963}`

## Description

> Power reveals the secret.

## TL;DR

Differential Power Analysis (DPA) on a CSV of power traces. The correct key digit at each position produces a higher peak in the averaged power trace.

## Analysis

The CSV has 60,000 rows with columns: `position`, `guess`, `trace_num`, `sample`, `power_mW`.

- 6 positions (digits of a PIN/key)
- 10 guesses per position (0-9)
- 20 traces per guess
- 50 samples per trace

This is a classic DPA setup: when the guessed key byte matches the actual key, the power consumption during processing is higher due to more bit transitions (Hamming weight/distance correlation).

## Solution

For each position, average all 20 traces per guess and find the peak value. The guess with the highest peak mean is the correct digit.

```python
#!/usr/bin/env python3
import csv, numpy as np

data = {}
with open("files/power_traces.csv") as f:
    for row in csv.DictReader(f):
        key = (int(row['position']), int(row['guess']))
        tn = int(row['trace_num'])
        data.setdefault(key, {}).setdefault(tn, [0.0]*50)[int(row['sample'])] = float(row['power_mW'])

for pos in range(6):
    best = max(range(10), key=lambda g: np.max(np.mean(list(data[(pos,g)].values()), axis=0)))
    print(best, end="")
# Output: 792963
```

## Flag

```
EH4X{792963}
```
