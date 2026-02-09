#!/usr/bin/env python3
import angr
import claripy

# Addresses from objdump
PRINT_FLAG = 0x08048596
NO_FLAG = 0x08048609
MAYBE_FLAG = 0x08048623
MAIN = 0x0804865f

print("[*] Loading binary...")
proj = angr.Project('./angr-y_binary', auto_load_libs=False)

print("[*] Setting up initial state...")
# Start from entry point
state = proj.factory.entry_state()

print("[*] Creating simulation manager...")
simgr = proj.factory.simulation_manager(state)

print("[*] Exploring paths to print_flag...")
print(f"[*] Target: 0x{PRINT_FLAG:x}")
print(f"[*] Avoid: 0x{NO_FLAG:x}")

# Explore: find print_flag, avoid no_flag
simgr.explore(find=PRINT_FLAG, avoid=NO_FLAG)

if simgr.found:
    print(f"[+] Found {len(simgr.found)} solution(s)!")
    solution = simgr.found[0]
    
    # Get stdin input
    print("[*] Extracting input...")
    stdin_data = solution.posix.dumps(0)
    print(f"[+] Input: {stdin_data}")
    print(f"[+] Input (decoded): {stdin_data.decode('latin-1')}")
else:
    print("[-] No solution found")
    print(f"    Active: {len(simgr.active)}")
    print(f"    Deadended: {len(simgr.deadended)}")
    print(f"    Avoid: {len(simgr.avoid)}")
