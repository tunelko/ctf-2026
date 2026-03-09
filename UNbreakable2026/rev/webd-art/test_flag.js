// Test flag by running the actual WASM in Chromium via Playwright
const { chromium } = require('playwright');

(async () => {
    const browser = await chromium.launch({
        headless: true,
        args: [
            '--no-sandbox',
            '--enable-features=WebAssemblyStringBuiltins',
        ]
    });

    const page = await browser.newPage();

    // Listen for console messages
    page.on('console', msg => console.log('CONSOLE:', msg.text()));
    page.on('pageerror', err => console.log('PAGE_ERROR:', err.message));

    // Navigate to the challenge page
    await page.goto('http://localhost:8888/index.html', { waitUntil: 'networkidle', timeout: 15000 });

    // Wait for WASM to load
    await page.waitForTimeout(3000);

    // Flags to test
    const flags = [
        'CTF{7h3_w3b_15_4_l1e_rng_15_de73rm1n15m}',
        'CTF{7h3_w3b_15_4_lie_rng_15_de73rm1ni5m}',
        'CTF{7h3_w3b_15_4_l13_rng_15_d373rm1n15m}',
        'CTF{7h3_w3b_15_4_li3_rng_15_d373rm1ni5m}',
    ];

    for (const flag of flags) {
        console.log(`\nTesting: ${flag}`);

        // Clear input and type the flag
        await page.fill('#phrase', flag);

        // Click render button
        await page.click('#renderBtn');

        // Wait for processing
        await page.waitForTimeout(2000);

        // Check canvas for "CERTIFICATE UNLOCKED" text
        const canvasText = await page.evaluate(() => {
            const canvas = document.querySelector('canvas');
            if (!canvas) return 'NO CANVAS';
            const ctx = canvas.getContext('2d');
            // Try to read rendered text by checking specific pixels or other methods
            return document.title || 'checked';
        });

        console.log(`  Result: ${canvasText}`);
    }

    await browser.close();
})().catch(err => {
    console.error('Error:', err.message);
    process.exit(1);
});
