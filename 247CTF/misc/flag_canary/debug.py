#!/usr/bin/env python3
import subprocess
import os

# Create flag.txt
with open('flag.txt', 'w') as f:
    f.write('247CTF{test_flag_here}')

# Run with input
proc = subprocess.Popen(['./canary'], 
    stdin=subprocess.PIPE, 
    stdout=subprocess.PIPE, 
    stderr=subprocess.PIPE)

# Send test input
proc.stdin.write(b'A' * 56 + b'\n')
proc.stdin.flush()

output = proc.stdout.read(1000)
print(output.decode())
