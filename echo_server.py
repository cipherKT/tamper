#!/usr/bin/env python3
"""
echo_server.py — tamper test server
Echoes back method, headers, and body of every incoming request as JSON.
Usage: python3 echo_server.py
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class EchoHandler(BaseHTTPRequestHandler):

    def handle_request(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b""

        try:
            body_parsed = json.loads(body_bytes)
        except Exception:
            # Try form-encoded or plain text
            body_parsed = body_bytes.decode("utf-8", errors="replace")

        response = {
            "method":  self.command,
            "path":    self.path,
            "headers": dict(self.headers),
            "body":    body_parsed,
        }

        payload = json.dumps(response, indent=2).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    # Handle all HTTP methods
    do_GET     = handle_request
    do_POST    = handle_request
    do_PUT     = handle_request
    do_PATCH   = handle_request
    do_DELETE  = handle_request
    do_OPTIONS = handle_request

    def log_message(self, fmt, *args):
        status = args[1] if len(args) > 1 else "-"
        color = "\033[32m" if status == "200" else "\033[31m"
        print(f"  {color}{self.command:<8}\033[0m {self.path}  →  {status}")


if __name__ == "__main__":
    host, port = "127.0.0.1", 8000
    server = HTTPServer((host, port), EchoHandler)
    print(f"\033[1m  echo server running on http://{host}:{port}\033[0m")
    print("  press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped.")
