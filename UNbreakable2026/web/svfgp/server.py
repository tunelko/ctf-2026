#!/usr/bin/env python3
"""Simple HTTP server for the exploit."""
import os
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

PORT = 9999
DIR = os.path.dirname(os.path.abspath(__file__))

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/report":
            ts = time.strftime("%H:%M:%S")
            for k, v in params.items():
                val = v[0] if v else ""
                print(f"  [{ts}] {k} = {val}", flush=True)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b"ok")
        elif parsed.path == "/" or parsed.path.startswith("/#"):
            with open(os.path.join(DIR, "exploit.html"), "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET")
        self.end_headers()

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[*] Serving on :{PORT}", flush=True)
    server.serve_forever()
