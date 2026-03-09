const http = require('http');
const { spawn } = require('child_process');
const WebSocket = require('/usr/share/nodejs/ws/index.js');

const CDP_PORT = 9223;
const chrome = spawn('chromium', [
    '--headless', '--no-sandbox', '--disable-gpu',
    `--remote-debugging-port=${CDP_PORT}`,
    'about:blank'
], { stdio: 'ignore' });

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function fetchJSON(path) {
    return new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${CDP_PORT}${path}`, res => {
            let d = ''; res.on('data', c => d += c); res.on('end', () => resolve(JSON.parse(d)));
        }).on('error', reject);
    });
}

let msgId = 1;
function send(ws, method, params = {}) {
    const id = msgId++;
    return new Promise((resolve) => {
        const h = (data) => {
            const msg = JSON.parse(data.toString());
            if (msg.id === id) { ws.removeListener('message', h); resolve(msg.result); }
        };
        ws.on('message', h);
        ws.send(JSON.stringify({ id, method, params }));
    });
}

async function main() {
    await sleep(2000);
    const targets = await fetchJSON('/json');
    const ws = new WebSocket(targets.find(t => t.type === 'page').webSocketDebuggerUrl);
    await new Promise(r => ws.on('open', r));

    await send(ws, 'Runtime.enable');
    await send(ws, 'Console.enable');
    await send(ws, 'Page.enable');

    ws.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        if (msg.method === 'Runtime.consoleAPICalled') {
            const args = msg.params.args.map(a => a.value !== undefined ? a.value : (a.description || a.type)).join(' ');
            console.log('[CONSOLE]', args);
        }
        if (msg.method === 'Runtime.exceptionThrown') {
            const det = msg.params.exceptionDetails;
            console.log('[EXCEPTION]', det.text, det.exception?.description || '');
        }
    });

    // Navigate to original page
    await send(ws, 'Page.navigate', { url: 'http://localhost:8888/index.html' });
    await sleep(5000);

    // Check if page loaded successfully
    let r = await send(ws, 'Runtime.evaluate', {
        expression: `document.title`,
        returnByValue: true
    });
    console.log('Title:', r.result.value);

    // Check canvas exists
    r = await send(ws, 'Runtime.evaluate', {
        expression: `!!document.getElementById('c') && !!document.getElementById('phrase')`,
        returnByValue: true
    });
    console.log('Elements exist:', r.result.value);

    // Try a test input
    console.log('\n--- Testing CTF{test_input_1234} ---');
    await send(ws, 'Runtime.evaluate', {
        expression: `document.getElementById('phrase').value = 'CTF{test_input_1234}';`
    });
    await send(ws, 'Runtime.evaluate', {
        expression: `document.getElementById('renderBtn').click();`
    });
    await sleep(2000);

    // Try to read canvas text by checking what was drawn
    // Let's look at the canvas context operations
    r = await send(ws, 'Runtime.evaluate', {
        expression: `
            // Get canvas and try to read what's drawn
            const canvas = document.getElementById('c');
            const ctx = canvas.getContext('2d');
            // Take a screenshot of a region where text might appear
            const imageData = ctx.getImageData(0, 0, 700, 500);
            // Check if there are non-black pixels (indicating something was drawn)
            let nonBlack = 0;
            for (let i = 0; i < imageData.data.length; i += 4) {
                if (imageData.data[i] > 20 || imageData.data[i+1] > 20 || imageData.data[i+2] > 20) nonBlack++;
            }
            'Non-black pixels: ' + nonBlack;
        `,
        returnByValue: true
    });
    console.log(r.result.value);

    // Try another approach - intercept fillText to see what text gets drawn
    console.log('\n--- Intercepting fillText ---');
    await send(ws, 'Runtime.evaluate', {
        expression: `
            const canvas = document.getElementById('c');
            const ctx = canvas.getContext('2d');
            const origFillText = ctx.fillText.bind(ctx);
            const drawnTexts = [];
            ctx.fillText = function(text, x, y) {
                drawnTexts.push({text, x, y});
                console.log('fillText: ' + JSON.stringify({text, x, y}));
                return origFillText(text, x, y);
            };
            window._drawnTexts = drawnTexts;
            'fillText intercepted';
        `,
        returnByValue: true
    });
    console.log('Interceptor set up');

    // Click render again
    await send(ws, 'Runtime.evaluate', {
        expression: `
            document.getElementById('phrase').value = 'CTF{test_input_1234}';
            document.getElementById('renderBtn').click();
        `
    });
    await sleep(2000);

    r = await send(ws, 'Runtime.evaluate', {
        expression: `JSON.stringify(window._drawnTexts)`,
        returnByValue: true
    });
    console.log('\nDrawn texts:', r.result.value);

    // Try with empty input
    console.log('\n--- Testing empty input ---');
    await send(ws, 'Runtime.evaluate', {
        expression: `
            window._drawnTexts.length = 0;
            document.getElementById('phrase').value = '';
            document.getElementById('renderBtn').click();
        `
    });
    await sleep(2000);
    r = await send(ws, 'Runtime.evaluate', {
        expression: `JSON.stringify(window._drawnTexts)`,
        returnByValue: true
    });
    console.log('Drawn texts (empty):', r.result.value);

    chrome.kill();
    process.exit(0);
}

main().catch(e => { console.error(e); chrome.kill(); process.exit(1); });
