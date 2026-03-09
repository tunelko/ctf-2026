#!/usr/bin/env python3
"""Extract actual expected values from the running binary using GDB."""
import subprocess
import re
import struct

# Strategy:
# 1. Run the binary under GDB with a test input
# 2. The binary uses futex for synchronization - break when it's about to print the result
# 3. Search heap memory for our known pattern (first expected value should be near 0x7FFFFFFF or 0xFFFFFFFF)
# 4. Read the 16 consecutive 64-bit values

# The VM memory is likely a large malloc'd array of int64_t.
# Memory addresses 137-152 in the VM correspond to byte offsets 137*8 to 152*8 from the array base.

# First, let's try to find the memory base by searching for characteristic values
# near each other.

gdb_script = """
set pagination off
set confirm off
set follow-fork-mode parent
set detach-on-fork off

file ./locked_in
# Use a short input to make it finish quickly
run flag_verifier.bin <<< "dice{AAAAAAAAAAAAAAAAAAAAAAAA}"

# After it finishes (or we catch the exit), search for the expected values
# The process should still be around. Let's try catching a thread.
# Actually, let's use a different approach: break before exit.

# Restart with a breakpoint on the write syscall for the result message
# Better: let's just set a breakpoint and search memory

quit
"""

# Let's try a different approach: use /proc/pid/mem to read the memory
# while the process is running, or use ptrace via GDB.

# Actually, simplest: write an LD_PRELOAD library that intercepts something
# to dump the VM memory. But that's complex.

# Even simpler: use the fact that the expected values are computed BEFORE
# any flag processing. Let's use strace to find the memory addresses
# and then use GDB to read them.

# OR: just search for the expected values in a core dump.

# Actually, let me try a much simpler approach: patch the bytecode to print
# the expected values. Or write a proper multi-threaded emulator.

# Let me try GDB with breakpoints on the futex-related syscall and memory search.

print("Attempting to extract expected values via GDB memory search...")

gdb_cmds = r"""
set pagination off
set confirm off
set print elements 0

file ./locked_in

# Break on the write() syscall that prints "Flag rejected"
# The binary uses write(1, ...). Let's break on write.
# Actually, let's break when the binary outputs text.

# Strategy: break on exit_group syscall
catch syscall exit_group

run flag_verifier.bin <<< "dice{AAAAAAAAAAAAAAAAAAAAAAAA}"

# Now search memory for our expected first value
# With W=0: first expected = 0x7FFFFFFF = 2147483647 as int64
# With W=1: first expected = 0xFFFFFFFF = 4294967295 as int64

# Get the heap range
info proc mappings

# Search for 0x7FFFFFFF in the heap region
# The value is stored as int64, so we search for the 8-byte pattern
find /g $rsp-0x1000000, $rsp+0x1000000, 0x7FFFFFFF

# Also search for 0xFFFFFFFF (W=1 case)
find /g $rsp-0x1000000, $rsp+0x1000000, (long long)0xFFFFFFFF

quit
"""

proc = subprocess.run(
    ['gdb', '-batch', '-ex', 'set pagination off',
     '-ex', 'set confirm off',
     '-ex', 'file ./locked_in',
     '-ex', 'catch syscall exit_group',
     '-ex', 'run flag_verifier.bin <<< "dice{AAAAAAAAAAAAAAAAAAAAAAAA}"',
     '-ex', 'info proc mappings',
     '-ex', 'find /g 0x400000, 0x500000, (long long)0x7FFFFFFF',
     '-ex', 'find /g 0x400000, 0x500000, (long long)0xFFFFFFFF',
     '-ex', 'quit'],
    capture_output=True, timeout=15, cwd='/home/student/ctfs/diceCTF2026/rev/locked-in'
)
print(f"GDB stdout:\n{proc.stdout.decode(errors='replace')[-3000:]}")
print(f"GDB stderr:\n{proc.stderr.decode(errors='replace')[-500:]}")
