// Node.js CDP script to debug the WASM challenge
const http = require('http');
const { spawn } = require('child_process');
const WebSocket = require('/usr/share/nodejs/ws/index.js');

const CDP_PORT = 9222;

const chrome = spawn('chromium', [
    '--headless',
    '--no-sandbox',
    '--disable-gpu',
    `--remote-debugging-port=${CDP_PORT}`,
    '--disable-web-security',
    'about:blank'
], { stdio: 'ignore' });

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function fetchJSON(path) {
    return new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${CDP_PORT}${path}`, res => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(JSON.parse(data)));
        }).on('error', reject);
    });
}

let msgId = 1;
function sendCommand(ws, method, params = {}) {
    const id = msgId++;
    return new Promise((resolve) => {
        const handler = (data) => {
            const msg = JSON.parse(data.toString());
            if (msg.id === id) {
                ws.removeListener('message', handler);
                resolve(msg.result);
            }
        };
        ws.on('message', handler);
        ws.send(JSON.stringify({ id, method, params }));
    });
}

async function main() {
    await sleep(2000);

    const targets = await fetchJSON('/json');
    const pageTarget = targets.find(t => t.type === 'page');
    const ws = new WebSocket(pageTarget.webSocketDebuggerUrl);
    await new Promise(r => ws.on('open', r));

    await sendCommand(ws, 'Runtime.enable');
    await sendCommand(ws, 'Console.enable');
    await sendCommand(ws, 'Page.enable');

    // Collect console messages
    const consoleMessages = [];
    ws.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        if (msg.method === 'Runtime.consoleAPICalled') {
            const args = msg.params.args.map(a => a.value || a.description || a.type).join(' ');
            consoleMessages.push(args);
            console.log('[CONSOLE]', args);
        }
        if (msg.method === 'Runtime.exceptionThrown') {
            console.log('[EXCEPTION]', msg.params.exceptionDetails.text);
        }
    });

    // Navigate to debug page
    await sendCommand(ws, 'Page.navigate', { url: 'http://localhost:8888/debug.html' });
    await sleep(6000);

    // Get page log
    const result = await sendCommand(ws, 'Runtime.evaluate', {
        expression: `document.getElementById('log').textContent`,
        returnByValue: true
    });
    console.log('\n=== PAGE LOG ===');
    console.log(result.result.value);

    // Get WASM exports
    const exportsResult = await sendCommand(ws, 'Runtime.evaluate', {
        expression: `JSON.stringify(Object.keys(window.wasmExports || {}))`,
        returnByValue: true
    });
    console.log('\n=== WASM EXPORTS ===');
    console.log(exportsResult.result.value);

    // Enter a test flag and click render
    await sendCommand(ws, 'Runtime.evaluate', {
        expression: `
            document.getElementById('phrase').value = 'CTF{test_input_1234}';
            document.getElementById('renderBtn').click();
        `
    });
    await sleep(3000);

    // Check console output after render
    const logAfter = await sendCommand(ws, 'Runtime.evaluate', {
        expression: `document.getElementById('log').textContent`,
        returnByValue: true
    });
    console.log('\n=== AFTER RENDER ===');
    console.log(logAfter.result.value);

    chrome.kill();
    process.exit(0);
}

main().catch(e => { console.error(e); chrome.kill(); process.exit(1); });
