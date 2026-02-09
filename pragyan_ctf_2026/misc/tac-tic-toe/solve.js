#!/usr/bin/env node
/**
 * Tac Tic Toe - WASM Patching Exploit
 *
 * This script loads the patched WASM binary where the AI plays poorly
 * instead of optimally, allowing us to win and get the flag.
 *
 * Requirements:
 * - Node.js
 * - main_patched.wasm (patched WASM binary)
 * - wasm_exec.js (Go WASM runtime)
 */

const fs = require("fs");
const crypto = require("crypto");

// Polyfill for crypto
if (!globalThis.crypto) {
  globalThis.crypto = {
    getRandomValues: (arr) => crypto.randomFillSync(arr)
  };
}

require("./wasm_exec.js");

async function main() {
  console.log("[*] Starting Tac Tic Toe exploit...\n");

  // Step 1: Get session and proof seed from server
  console.log("[+] Requesting new game session...");
  const startRes = await fetch("https://tac-tic-toe.ctf.prgy.in/start");
  const startData = await startRes.json();

  console.log(`[+] Session ID: ${startData.session_id}`);
  console.log(`[+] Proof Seed: ${startData.proof_seed}\n`);

  // Step 2: Load patched WASM
  console.log("[+] Loading patched WASM binary...");
  const go = new Go();
  const wasmBuffer = fs.readFileSync("./main_patched.wasm");
  const result = await WebAssembly.instantiate(wasmBuffer, go.importObject);
  go.run(result.instance);
  console.log("[+] WASM loaded successfully\n");

  // Step 3: Initialize game with server's seed
  console.log("[+] Initializing game with proof seed...");
  InitGame(startData.proof_seed);
  console.log(`[+] Game status: ${globalThis.gameStatus}\n`);

  // Step 4: Play winning moves (left column: 0, 3, 6)
  console.log("[+] Playing moves...");
  const winningMoves = [0, 3, 6];

  for (const move of winningMoves) {
    if (globalThis.gameStatus !== "playing") {
      console.log(`[!] Game ended early with status: ${globalThis.gameStatus}`);
      break;
    }

    PlayerMove(move);
    console.log(`    Move ${move}: ${globalThis.gameStatus}`);
  }

  console.log();

  // Step 5: Get win data
  if (globalThis.gameStatus === "win") {
    console.log("[+] Game won! Getting win data...");
    const data = GetWinData();

    console.log(`[+] Move sequence: [${data.moves.join(", ")}]`);
    console.log(`[+] Proof: ${data.proof}\n`);

    // Step 6: Submit to server
    console.log("[+] Submitting win to server...");
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

    const result = await res.text();
    console.log("\n[+] Server response:");
    console.log("=" .repeat(60));
    console.log(result);
    console.log("=".repeat(60));

    // Check if we got the flag
    if (result.includes("p_ctf{") || result.includes("flag")) {
      console.log("\n🎉 FLAG CAPTURED! 🎉");
    }
  } else {
    console.log(`[!] Failed to win. Final status: ${globalThis.gameStatus}`);
  }
}

// Run the exploit
main().catch(err => {
  console.error("[!] Error:", err);
  process.exit(1);
});
