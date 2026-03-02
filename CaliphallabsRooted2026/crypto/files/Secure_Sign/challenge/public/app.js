const API_URL = '/api';

document.addEventListener('DOMContentLoaded', async () => {
    const isDashboard = window.location.pathname.endsWith('dashboard.html');
    
    try {
        const res = await fetch(`${API_URL}/user`);
        if (res.ok) {
            if (!isDashboard) {
                window.location.href = 'dashboard.html';
            }
        } else {
            if (isDashboard) {
                window.location.href = 'index.html';
            }
        }
    } catch (err) {
        console.error("Session check failed", err);
    }
});

function switchTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('form').forEach(form => form.style.display = 'none');
    
    if (tab === 'login') {
        const loginBtn = document.querySelector('button[onclick="switchTab(\'login\')"]');
        if (loginBtn) loginBtn.classList.add('active');
        const loginForm = document.getElementById('login-form');
        if (loginForm) loginForm.style.display = 'block';
    } else {
        const regBtn = document.querySelector('button[onclick="switchTab(\'register\')"]');
        if (regBtn) regBtn.classList.add('active');
        const regForm = document.getElementById('register-form');
        if (regForm) regForm.style.display = 'block';
    }
    const msg = document.getElementById('auth-msg');
    if (msg) msg.textContent = '';
}

function showMessage(msg, type = 'info') {
    const el = document.getElementById('auth-msg');
    if (el) {
        el.textContent = msg;
        el.className = `message ${type}`;
    } else {
        if (type === 'invalid') alert(msg);
    }
}

const loginForm = document.getElementById('login-form');
if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;

        try {
            const res = await fetch(`${API_URL}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            const data = await res.json();
            
            if (res.ok) {
                window.location.href = 'dashboard.html';
            } else {
                showMessage(data.message, 'invalid');
            }
        } catch (err) {
            showMessage('Error de Conexión', 'invalid');
        }
    });
}

const regForm = document.getElementById('register-form');
if (regForm) {
    regForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('reg-email').value;
        const password = document.getElementById('reg-password').value;

        try {
            const res = await fetch(`${API_URL}/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            const data = await res.json();
            
            if (res.ok) {
                showMessage('¡Registro exitoso! Por favor inicia sesión.', 'valid');
                setTimeout(() => switchTab('login'), 1500);
            } else {
                showMessage(data.message, 'invalid');
            }
        } catch (err) {
            showMessage('Error de Conexión', 'invalid');
        }
    });
}

function logout() {
    document.cookie = "jwt=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    window.location.href = 'index.html';
}

let latestSignatures = [];

async function signDocuments() {
    const fileInput = document.getElementById('sign-files');
    const files = fileInput.files;
    
    if (files.length === 0) return alert("Por favor selecciona al menos un archivo para firmar");

    const documentsToSign = [];

    const toBase64 = file => new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => resolve(reader.result.split(',')[1]);
        reader.onerror = error => reject(error);
    });

    try {
        for (let i = 0; i < files.length; i++) {
            const b64 = await toBase64(files[i]);
            documentsToSign.push({
                filename: files[i].name,
                content: b64
            });
        }

        const res = await fetch(`${API_URL}/sign`, { 
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ files: documentsToSign }) 
        });
        const data = await res.json();
        
        if (res.ok) {
            latestSignatures = data.results;
            
            const resultBox = document.getElementById('sign-result');
            const list = document.getElementById('signature-list');
            list.innerHTML = '';
            
            latestSignatures.forEach(item => {
                const li = document.createElement('li');
                if (item.error) {
                    li.innerHTML = `<span style="color:red">✘ ${item.filename}: ${item.error}</span>`;
                } else {
                    li.innerHTML = `<span style="color:#00d2d3">✔ ${item.filename}</span> (Firma generada)`;
                }
                list.appendChild(li);
            });
            
            resultBox.classList.remove('hidden');
        } else {
            alert("Error: " + data.message);
        }
    } catch (err) {
        alert("Fallo al firmar");
        console.error(err);
    }
}

async function downloadSignaturesZip() {
    if (!latestSignatures || latestSignatures.length === 0) return alert("No hay firmas para descargar");
    
    const zip = new JSZip();
    let count = 0;
    
    latestSignatures.forEach(item => {
        if (!item.error && item.signature) {
            zip.file(item.filename + ".hex", item.signature);
            count++;
        }
    });
    
    if (count === 0) return alert("No hay firmas válidas para comprimir");
    
    const content = await zip.generateAsync({type: "blob"});
    const url = window.URL.createObjectURL(content);
    const a = document.createElement('a');
    a.href = url;
    a.download = "firmas.zip";
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
}

async function verifySignature() {
    const fileInput = document.getElementById('verify-file');
    const sigFileInput = document.getElementById('verify-sig-file');
    const sigText = document.getElementById('verify-signature-text').value;

    if (fileInput.files.length === 0) return alert("Por favor selecciona el documento original");
    if (sigFileInput.files.length === 0 && !sigText) return alert("Por favor proporciona la firma (archivo o texto hex)");

    const formData = new FormData();
    formData.append('document', fileInput.files[0]);

    if (sigFileInput.files.length > 0) {
        formData.append('signature_file', sigFileInput.files[0]);
    } else {
        formData.append('signature', sigText);
    }

    try {
        const res = await fetch(`${API_URL}/verify`, { method: 'POST', body: formData });
        const data = await res.json();
        
        const resultBox = document.getElementById('verify-result');
        resultBox.classList.remove('hidden');
        
        if (data.valid) {
            resultBox.innerHTML = '<span class="valid">✔ Firma Verificada: El documento es Auténtico.</span>';
        } else if (data.message) {
             resultBox.innerHTML = `<span class="invalid">✘ Error: ${data.message}</span>`;
        } else {
            resultBox.innerHTML = '<span class="invalid">✘ Verificación Fallida: Firma o Documento Inválido.</span>';
        }
    } catch (err) {
        alert("Fallo en la solicitud de verificación");
    }
}
