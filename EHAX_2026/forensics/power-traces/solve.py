#!/usr/bin/env python3
"""Power Traces - DPA side-channel analysis solver"""
import csv
import numpy as np

DATA_FILE = "files/power_traces.csv"

# Load data: (position, guess) -> list of traces
data = {}
with open(DATA_FILE) as f:
    reader = csv.DictReader(f)
    for row in reader:
        pos = int(row['position'])
        guess = int(row['guess'])
        trace_num = int(row['trace_num'])
        sample = int(row['sample'])
        power = float(row['power_mW'])

        key = (pos, guess)
        if key not in data:
            data[key] = {}
        if trace_num not in data[key]:
            data[key][trace_num] = [0.0] * 50
        data[key][trace_num][sample] = power

# DPA: for each position, the correct guess has the highest peak in the mean trace
flag_digits = []
for pos in range(6):
    best_guess = -1
    best_peak = -1
    for guess in range(10):
        traces = np.array(list(data[(pos, guess)].values()))
        peak_mean = np.max(np.mean(traces, axis=0))
        if peak_mean > best_peak:
            best_peak = peak_mean
            best_guess = guess
    flag_digits.append(best_guess)

pin = "".join(map(str, flag_digits))
flag = f"EHAX{{{pin}}}"
print(f"FLAG: {flag}")
