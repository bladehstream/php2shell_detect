#!/usr/bin/env python3
"""Mock web server that serves fake PHP X-Powered-By banners for testing the scanner."""

import http.server
import threading
import time

VERSIONS = {
    "/index.php": "8.2.34",
    "/info.php": "8.3.36",
    "/test.php": "7.4.33",
    "/phpinfo.php": "8.5.11",
}

# Simulates a hardened host: expose_php = Off (no X-Powered-By), no session
# cookies, but php-fpm answering missing .php scripts with "File not found."
HARDENED_PATHS = {"/missing.php"}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]
        if path.startswith("/nonexistent-") and path.endswith(".php"):
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            body = b"File not found."
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path in HARDENED_PATHS:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path in VERSIONS:
            self.send_response(200)
            self.send_header("X-Powered-By", "PHP/" + VERSIONS[path])
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 8080), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print("mock server on 127.0.0.1:8080")
    time.sleep(20)
    srv.shutdown()
