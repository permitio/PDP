#!/usr/bin/env python3
# ruff: noqa: T201, N802
"""
Test server for watchdog tests.
This server listens on a configurable port and responds to various commands:
- GET /ping: Returns "pong" to verify the server is running
- GET /health: Returns health status of the server
- GET /status: Returns the server uptime and request count
- POST /crash: Terminates the server to simulate a crash
- POST /unhealthy: Makes /health return a non-200 status code
- POST /unresponsive: Makes /health halt and not respond
"""

import argparse
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

start_time = time.time()
request_count = 0
is_healthy = True
is_responsive = True


class TestHandler(BaseHTTPRequestHandler):
    def _set_headers(self, content_type="text/plain", status_code=200):
        self.send_response(status_code)
        self.send_header("Content-type", content_type)
        self.end_headers()

    def do_GET(self):
        global request_count
        request_count += 1

        if self.path == "/ping":
            self._set_headers()
            self.wfile.write(b"pong")

        elif self.path == "/health":
            if not is_responsive:
                # Simulate hanging response by not returning anything
                time.sleep(10)

            if is_healthy:
                self._set_headers()
                self.wfile.write(b"healthy")
            else:
                self._set_headers(status_code=503)
                self.wfile.write(b"unhealthy")

        elif self.path == "/status":
            self._set_headers("application/json")
            status = {
                "pid": os.getpid(),
                "uptime": time.time() - start_time,
                "request_count": request_count,
                "is_healthy": is_healthy,
                "is_responsive": is_responsive,
            }
            self.wfile.write(json.dumps(status).encode())

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")

    def do_POST(self):
        global request_count, is_healthy, is_responsive
        request_count += 1

        if self.path == "/crash":
            self._set_headers()
            self.wfile.write(b"Crashing now...")
            self.wfile.flush()
            # Force crash the server with SIGTERM
            raise SystemExit(12)

        elif self.path == "/unhealthy":
            is_healthy = False
            self._set_headers()
            self.wfile.write(b"Health status set to unhealthy")

        elif self.path == "/unresponsive":
            is_responsive = False
            self._set_headers()
            self.wfile.write(b"Health endpoint set to unresponsive")

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")


def run_server(port):
    server_address = ("", port)
    httpd = HTTPServer(server_address, TestHandler)
    print(f"Starting test server on port {port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Server shutting down")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test HTTP server")
    parser.add_argument("--port", type=int, default=8080, help="Port to run the server on")
    args = parser.parse_args()

    run_server(args.port)
