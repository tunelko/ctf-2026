# Tac Tic Toe - WASM Patching Challenge

**Category:** Web/Reversing
**URL:** https://tac-tic-toe.ctf.prgy.in
**Challenge:** "Have you played tic tac toe? Ok, but can you win?"

## Flag
`p_ctf{W@sM@_!s_Fas&t_Bu?_$ecur!ty}`

*"WASM is Fast But Security"* - A play on WebAssembly's speed vs security trade-offs.

---

## Challenge Overview

A WebAssembly-based tic-tac-toe game where the AI plays perfectly using minimax algorithm. The goal is to win the game, but the AI is unbeatable with optimal play. The solution requires patching the WASM binary to make the AI play poorly.

---

## Analysis

### Game Flow

1. **GET /start** → Returns `session_id` and `proof_seed`
2. **WASM Initialization** → Game initializes with the seed
3. **Gameplay** → Each move (player + AI) updates a rolling `proof` via `UpdateProof()`
4. **Win Submission** → POST /win with move sequence and proof for server verification

### Key Discovery

The server validates the proof against the seed and moves but **does not enforce that the AI played optimally**. It only:
- Replays the moves
- Checks the proof matches

This means if we patch the WASM to make the AI play poorly, the proof will still be valid because `UpdateProof()` depends only on:
- Move positions
- The seed
- NOT on how the AI chose its move

---

## Vulnerability

The proof mechanism has no integrity check on the AI's decision-making logic. The proof only verifies:
```
proof = UpdateProof(seed, move_position, counter)
```

It doesn't validate that the AI used minimax or played optimally. This allows us to modify the AI's behavior while maintaining a valid proof.

---

## Exploitation Steps

### 1. Download and Analyze WASM

```bash
curl -o main.wasm https://tac-tic-toe.ctf.prgy.in/main.wasm
```

### 2. Convert WASM to WAT (Text Format)

```bash
wasm2wat main.wasm -o main.wat
```

### 3. Locate AI Logic

Find the `main.playPerfectMove` function which uses minimax to select the best move.

**Key sections to patch:**

**Line 520166** - Initial best score:
```wat
;; Original (looks for maximum score)
i64.const -1000

;; Patched (looks for minimum score)
i64.const 1000
```

**Line 520297** - Score comparison:
```wat
;; Original (picks best move - highest score)
i64.lt_s

;; Patched (picks worst move - lowest score)
i64.gt_s
```

### 4. Apply Patches

Edit `main.wat`:
- Line 520166: Change `i64.const -1000` to `i64.const 1000`
- Line 520297: Change `i64.lt_s` to `i64.gt_s`

This inverts the minimax logic, making the AI choose the worst possible move instead of the best.

### 5. Convert Back to WASM

```bash
wat2wasm main.wat -o main_patched.wasm
```

### 6. Create Exploit Script

```javascript
// solve.js
const fs = require("fs");
require("./wasm_exec.js");

async function main() {
  // Get session and seed from server
  const startRes = await fetch("https://tac-tic-toe.ctf.prgy.in/start");
  const startData = await startRes.json();
  console.log(`Session: ${startData.session_id}, Seed: ${startData.proof_seed}`);

  // Load patched WASM
  const go = new Go();
  const wasmBuffer = fs.readFileSync("./main_patched.wasm");
  const result = await WebAssembly.instantiate(wasmBuffer, go.importObject);
  go.run(result.instance);

  // Initialize with server's seed
  InitGame(startData.proof_seed);

  // Play winning moves: left column [0, 3, 6]
  for (const move of [0, 3, 6]) {
    if (globalThis.gameStatus !== "playing") break;
    PlayerMove(move);
    console.log(`Played move: ${move}, Status: ${globalThis.gameStatus}`);
  }

  // Get win data (moves + proof)
  const data = GetWinData();
  console.log(`Moves: ${data.moves}, Proof: ${data.proof}`);

  // Submit to server
  const payload = {
    session_id: startData.session_id,
    final_board: data.moves,
    proof: data.proof
  };

  const res = await fetch("https://tac-tic-toe.ctf.prgy.in/win", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  const result_text = await res.text();
  console.log(result_text);
}

main();
```

### 7. Execute

```bash
# Download wasm_exec.js from Go's WASM support
curl -o wasm_exec.js https://tac-tic-toe.ctf.prgy.in/wasm_exec.js

# Run exploit
node solve.js
```

---

## How It Works

With the patched WASM:

**Move 0 (Player → position 0):**
```
X | . | .
---------
. | . | .
---------
. | . | .
```

**AI Move (picks worst → position 1):**
```
X | O | .
---------
. | . | .
---------
. | . | .
```

**Move 3 (Player → position 3):**
```
X | O | .
---------
X | . | .
---------
. | . | .
```

**AI Move (picks worst → position 2):**
```
X | O | O
---------
X | . | .
---------
. | . | .
```

**Move 6 (Player → position 6) - WIN!**
```
X | O | O
---------
X | . | .
---------
X | . | .
```

Player wins with left column (positions 0, 3, 6).

---

## Key Takeaways

1. **Proof mechanism was flawed** - Only validated move sequence, not AI decision quality
2. **WASM is reversible** - Can be decompiled, analyzed, and patched
3. **Client-side validation is insufficient** - Server should validate game logic, not just cryptographic proofs
4. **Minimax inversion** - Changing score comparison and initial value completely inverts AI behavior

---

## Tools Used

- `wasm2wat` - WASM to WAT converter (from WABT)
- `wat2wasm` - WAT to WASM compiler
- `Node.js` - JavaScript runtime for WASM execution
- Text editor - For patching WAT file

---

## Files

```
/root/ctf/pragyanctf/tac-tic-toe/
├── WRITEUP.md          # This file
├── solve.js            # Exploit script
├── main.wasm           # Original WASM (1.8MB)
├── main.wat            # Disassembled WAT
├── main_patched.wasm   # Patched WASM
└── wasm_exec.js        # Go WASM runtime
```

---

## Alternative Approaches Considered

1. ❌ **Brute-force move sequences** - AI is perfect, no valid winning sequence exists
2. ❌ **Manipulate proof calculation** - Too complex, server validates against seed
3. ❌ **Race conditions** - Single-player game, no concurrency issues
4. ✅ **Patch AI logic** - Simple, effective, maintains valid proof

---

## References

- [WebAssembly Binary Toolkit (WABT)](https://github.com/WebAssembly/wabt)
- [Go WebAssembly Documentation](https://github.com/golang/go/wiki/WebAssembly)
- [Minimax Algorithm](https://en.wikipedia.org/wiki/Minimax)

---

## PoC

### Exploit Execution

<img src="tictactoe.png" alt="Exploit execution" width="800">

*Screenshot showing successful execution of the exploit with WASM patching and flag capture.*
