# diceminer

| Field       | Value                             |
|-------------|-----------------------------------|
| Platform    | DiceCTF 2026                      |
| Category    | web                               |
| Difficulty  | Medium                            |
| Connection  | `https://diceminer.chals.dicec.tf` |

## Description

> big rock become small paycheck

Web mining game: you mine blocks, earn DiceCoin (DC), buy better pickaxes, and if you accumulate 1,000,000 DC you can buy the flag. The `HAULING_RATE = 0.95` means you always pay 95% of what you mine as "hauling cost" — with normal play it's mathematically impossible to reach one million.

## Flag

```
dice{first_we_mine_then_we_cr4ft}
```

## TL;DR

IEEE 754 float precision bug: in JavaScript `2^53 + 1 === 2^53`. By starting at `x = 2^53 - 1` and digging in the `right` direction, the first step reaches block `2^53` (new, unmined) and all subsequent steps keep producing the same key `2^53` (precision overflow). The dig loop mines the same block `range` times, but `haulBase` counts it only once → profit of `earnings * range - cost_of_1_block`.

## Bug Analysis

### Digging Mechanics (server.js)

```javascript
const HAULING_RATE = 0.95;  // "big rock become small paycheck"

// In /api/dig:
let cx = user.x, cy = user.y;
let remaining = pickaxe.range;

while (remaining > 0) {
    cx += dx;          // ← BUG: if cx = 2^53, cx+1 === cx (float precision)
    cy += dy;
    const key = cx + ',' + cy;
    if (user.mined[key]) { remaining--; continue; }  // user.mined doesn't include the new block yet
    mined[key] = true;
    earnings += ore.reward;
    remaining--;
}

// After the loop:
let haulBase = 0;
for (const key of blocks) {  // blocks = Object.keys(mined) = 1 unique key!
    haulBase += ORES[getBlockType(bx, by)].reward;
}
const cost = Math.floor(haulBase * HAULING_RATE);  // cost of 1 block, not range blocks
const net = earnings - cost;                        // earnings=reward*range, cost=reward*0.95
```

### The Float Bug

```javascript
// In JavaScript (IEEE 754 double precision):
Number.MAX_SAFE_INTEGER = 2^53 - 1 = 9007199254740991

9007199254740992 + 1 === 9007199254740992  // TRUE! float precision lost
```

Starting at `x = 2^53 - 1`:
- Step 1: `cx = 2^53 - 1 + 1 = 2^53` → key `"9007199254740992,y"` → **new block**, not in `user.mined` → gets mined
- Step 2: `cx = 2^53 + 1 = 2^53` (float stuck!) → **same key** → `user.mined` not yet updated (only at the end of the loop) → gets mined again
- Steps 3..range: same → same block mined `range` times

Result with **Gold Pickaxe (range=100)** on a **diamond (reward=1500)**:
```
earnings  = 1500 * 100  = 150,000
haulBase  = 1500 * 1    =   1,500  (1 unique key in mined{})
cost      = floor(1500 * 0.95) = 1,425
net       = 150,000 - 1,425  = 148,575 DC per energy
```

### Why the Exploit Needs to Change y

After each `dig right`, the block `(2^53, y)` is stored in `user.mined`. The next dig at the same `y` would skip it on every step. That's why we change the `y` level on each dig — each depth is a fresh block.

## Exploitation Path (~50 energy out of 250 available)

| Phase | Pickaxe | Location | Net/dig | Energy |
|-------|---------|----------|---------|--------|
| 1 | Wooden (range=5) | y=0,-1,-2 (surface) | 41 DC | ~3 |
| 2 | Stone (range=15) | y=-5..-34 | 141-4215 DC | ~12 |
| 3 | Iron (range=40) | y=-8 (gold ore) | 3124 DC | 3 |
| 4 | Gold (range=100) | y=-61,-92,-105,-113 (diamond) | 148,575 DC | ~8 |

## Why Normal Play is Impossible

```
Theoretical max: 250 energy × gold_pickaxe × avg_net_per_block
= 250 × 100_blocks × (153.5 × 0.05)  = 191,875 DC
Flag cost: 1,000,000 DC
```
Impossible without the bug (4x short).

## Exploit

See `solve.py`.

```bash
python3 solve.py https://diceminer.chals.dicec.tf
```

## Discarded Approaches

1. **Race condition** → Node.js single-threaded, no async I/O in `/api/dig`, doesn't work
2. **Optimal column selection** → sum of the 250 best columns = 241K DC (insufficient)
3. **Balance overflow** → small integer numbers, no overflow
4. **Type confusion in `/api/buy`** → `item === 'flag'` strict, object causes harmless 500 crash
5. **Prototype pollution** → keys are always `"integer,integer"`, impossible to generate `__proto__`

## Key Lessons

- **`Number.MAX_SAFE_INTEGER` in JS**: beyond `2^53 - 1`, integer arithmetic with floats loses precision
- **Local vs. global state in loops**: `user.mined` is not updated until after the dig loop → blocks can be re-mined within the same iteration
- **`haulingBase` separate from `earnings`**: the separation between the mining loop and the cost calculation creates the exploitable discrepancy
- **"big rock become small paycheck"** = the hint about `HAULING_RATE` as a designed obstacle to make normal play impossible → look for a mathematical exploit

## References

- [IEEE 754 double precision](https://en.wikipedia.org/wiki/Double-precision_floating-point_format)
- [JavaScript Number.MAX_SAFE_INTEGER](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/MAX_SAFE_INTEGER)
