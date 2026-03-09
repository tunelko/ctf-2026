#!/usr/bin/env python3
"""Use GDB to trace the locked_in binary and extract key values."""
import subprocess
import re

# GDB script to:
# 1. Run the binary with test input
# 2. Break at the STORE handler to capture memory writes to addresses 137-152
# 3. Also trace the packed values sent to channel '.'

gdb_script = """
set pagination off
set confirm off

# First, find the VM memory array. The binary loads the program, creates VM struct.
# Let's look for the main VM execution function.

# Strategy: break on clone3 syscall to identify thread creation,
# then trace the STORE operations.

# Actually, let's try a simpler approach:
# The VM memory is allocated as a large array. Let's find where the
# futex calls happen and identify the memory base.

# Run with test input
run flag_verifier.bin <<< "dice{AAAAAAAAAAAAAAAAAAAAAAAA}"

# After it finishes, we can't inspect. Let's try catching it mid-execution.
quit
"""

# Actually, let's try a different approach: use /proc/pid/maps to find
# writable memory, and strace to find the memory base.

# Simpler: let's use ltrace or custom LD_PRELOAD to intercept futex calls
# and extract the VM memory base address.

# Even simpler: let's just binary-search for the expected values in the
# process memory. But we need the process to be alive.

# Let's try: write a small C program that LD_PRELOADs and hooks
# relevant calls to log the VM state.

# Actually the simplest approach: use the binary's own debug output.
# The worker threads print debug info (chars). But we saw no output...
# unless the threads die before printing.

# Let me check if the VM uses stdin/stdout directly
print("Testing binary output...")
result = subprocess.run(
    ['./locked_in', 'flag_verifier.bin'],
    input=b'dice{AAAAAAAAAAAAAAAAAAAAAAAA}\n',
    capture_output=True,
    timeout=5
)
print(f"stdout ({len(result.stdout)} bytes): {result.stdout}")
print(f"stderr ({len(result.stderr)} bytes): {result.stderr}")

# Now let's try GDB non-interactively
print("\nUsing GDB to trace memory stores...")
gdb_cmds = """
set pagination off
set confirm off
set print elements 0

# We need to find where memory[137] gets written
# The VM's STORE handler writes to vm->memory[addr]
# memory is likely a pointer in the VM struct

# Let's break at the point where the process is about to exit
# and search for our expected values in memory

# Use a temporary file for input
shell echo 'dice{AAAAAAAAAAAAAAAAAAAAAAAA}' > /tmp/locked_input.txt

# Set args
file ./locked_in
set args flag_verifier.bin < /tmp/locked_input.txt

# Break on exit
catch syscall exit_group

run < /tmp/locked_input.txt

# Now search for the expected value pattern in memory
# Expected[0] should be around 0x7FFFFFFF if FUTEX_WAKE returns 0
# Let's search for this value in memory

# Find all mapped memory regions
info proc mappings

# Search for the 0x7FFFFFFF value in the heap/data segments
# The VM memory is probably a large mmap'd region
find /g 0x400000, 0x800000, 0x7fffffff

quit
"""

proc = subprocess.run(
    ['gdb', '-batch', '-x', '/dev/stdin', './locked_in'],
    input=gdb_cmds.encode(),
    capture_output=True,
    timeout=30,
    cwd='/home/student/ctfs/diceCTF2026/rev/locked-in'
)
print(f"GDB stdout:\n{proc.stdout.decode(errors='replace')[-3000:]}")
print(f"GDB stderr:\n{proc.stderr.decode(errors='replace')[-1000:]}")
