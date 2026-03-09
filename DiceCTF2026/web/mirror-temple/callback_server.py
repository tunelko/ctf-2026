#!/usr/bin/env python3
import http.server
import urllib.parse
import sys

LOG = "/root/ctf/DiceCTF2026/web/mirror-temple/headers.log"

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self._log("GET")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        cl = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl)
        self._log("POST", body)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def _log(self, method, body=None):
        with open(LOG, "a") as f:
            f.write("\n=== %s %s ===\n" % (method, self.path[:300]))
            for k, v in self.headers.items():
                f.write("  %s: %s\n" % (k, v))
            if body:
                f.write("  BODY: %s\n" % body[:2000].decode("utf-8", errors="replace"))
            f.write("---\n")
        # Also print to stdout for immediate visibility
        print("[%s] %s" % (method, self.path[:200]), flush=True)
        if body:
            print("  BODY: %s" % body[:500].decode("utf-8", errors="replace"), flush=True)

    def log_message(self, fmt, *args):
        pass

http.server.HTTPServer(("0.0.0.0", 9999), Handler).serve_forever()
