# Heist V1

**Category:** BLOCKCHAIN
**Flag:** `EH4X{c4ll1ng_m4d3_s000_e45y_th4t_my_m0m_d03snt_c4ll_m3}`

## Description

> The government has released a new vault and now we can add proposals too, what?? Drain the VAULT.

## TL;DR

Delegatecall storage collision. `Vault.execute()` does unprotected `delegatecall` to `governance` address. `setGovernance()` has no auth check. Deploy malicious contract that overwrites slot 0 (paused=false) and slot 1 (admin=player) via delegatecall, then withdraw all funds.

## Analysis

**Vault.sol:**
- Slot 0: `paused` (bool) + `fee` (uint248) — packed
- Slot 1: `admin` (address) + `governance` (address) — packed
- `execute(bytes)` does `delegatecall` to `governance` — executes external code in Vault's storage context
- `setGovernance(address)` has **no access control** — anyone can change it
- `withdraw()` requires `!paused` and `msg.sender == admin`

**Governance.sol:**
- `setProposal(uint256 x)` writes to slot 0 (proposalCount)

The `delegatecall` in `execute()` runs the target contract's code but in the Vault's storage. By deploying a malicious contract that writes to slots 0 and 1, we can overwrite `paused` and `admin`.

## Solution

1. Deploy malicious contract with fallback that does `sstore(0, 0)` (unpause) and `sstore(1, caller())` (set admin to us)
2. Call `setGovernance(malicious_addr)` — no auth check
3. Call `execute(any_data)` — delegatecall triggers fallback, overwrites storage
4. Call `withdraw()` — now we're admin and vault is unpaused

```bash
python3 solve.py 135.235.193.111 1337
```

## Flag

```
EH4X{c4ll1ng_m4d3_s000_e45y_th4t_my_m0m_d03snt_c4ll_m3}
```
