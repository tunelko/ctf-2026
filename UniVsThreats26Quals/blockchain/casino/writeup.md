# Andromeda Casino - Horses

**Category:** BLOCKCHAIN
**Flag:** `UVT{Bl4ck_h0r5e_br0wn_h0r5e_m1nt_h0r5e}`

## Description

> Welcome to the greatest casino in the whole Andromeda Galaxy! Go to the Casino's Exchange and ask them for some free tokens. If you can multiply them, you're in for a stellar treat!

## TL;DR

Sui Move horse racing casino. Breed validation uses substring matching (`index_of`), allowing us to mint a horse with an arbitrarily long breed (e.g., `"MustangMustangMustang"`, length 21) that becomes the fastest horse (speed = breed length). Bet on it to win all stall coins, then solve with ≥150 coins.

## Analysis

Three Move modules on Sui:

- **casino_coin** — Creates CASINO_COIN currency with a shared TreasuryHolder
- **exchange** — Manages the challenge: `claim_coin` gives 100 free coins, `solve` requires ≥150 coins
- **stall** — Horse betting: mint horses, place bets, winner takes all

Key vulnerability in `stall::is_valid_breed`:
```move
public fun is_valid_breed(breed: String): bool {
    // Checks if any valid breed name is a SUBSTRING of the input
    if (string::index_of(&breed, &b) < breed_len) return true;
}
```

Horse speed is set to `string::length(&breed)`. So breed `"MustangMustangMustang"` (21 chars) passes validation (contains "Mustang") but has speed 21, beating Thoroughbred (12).

The min_bet check only charges 120 for exact `"Thoroughbred"` breed, so our custom horse costs only 50.

**Math:** Claim 100 → Bet 100 on fastest horse → Stall has 150 (100 + 50 initial) → Win all 150 → Solve.

## Solution

### Solve Script

Upload a Move module with entry functions for each step, then call them via the server's interactive menu.

```bash
cd blockchain/casino && python3 solve.py <HOST> <PORT>
```

## Flag

```
UVT{Bl4ck_h0r5e_br0wn_h0r5e_m1nt_h0r5e}
```
