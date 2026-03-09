// Deno script to load and analyze the WASM module

const wasmBytes = Deno.readFileSync("main.wasm");

console.log("WASM size:", wasmBytes.length);

// Try to compile with js-string builtins
try {
    const mod = await WebAssembly.compile(wasmBytes, { builtins: ['js-string'] } as any);
    console.log("Compiled with builtins!");

    const imports = WebAssembly.Module.imports(mod);
    console.log(`Imports: ${imports.length}`);

    // Group imports by module
    const byModule: Record<string, any[]> = {};
    for (const imp of imports) {
        if (!byModule[imp.module]) byModule[imp.module] = [];
        byModule[imp.module].push(imp);
    }
    for (const [mod, imps] of Object.entries(byModule)) {
        console.log(`  Module "${mod}": ${imps.length} imports`);
        if (mod !== "S") {
            for (const imp of imps) {
                console.log(`    ${imp.name}: ${imp.kind}`);
            }
        }
    }

    const exports = WebAssembly.Module.exports(mod);
    console.log(`\nExports: ${exports.length}`);
    for (const exp of exports) {
        console.log(`  ${exp.name}: ${exp.kind}`);
    }
} catch(e: any) {
    console.log("Compile error:", e.message);

    // Try without builtins
    try {
        const mod = await WebAssembly.compile(wasmBytes);
        console.log("Compiled without builtins!");
    } catch(e2: any) {
        console.log("Without builtins:", e2.message);
    }
}
