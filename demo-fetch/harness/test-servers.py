#!/usr/bin/env python3
"""Local deterministic test servers for the mcp-server-fetch verification.

Ports:
  8898  canary      - records every inbound hit to HITS_FILE, returns 200
  8899  redirector  - 302 redirects to the canary (SSRF-via-redirect PoC)
  8900  robots-deny - robots.txt disallows everything; serves /secret-page
  8901  honest      - small HTML page; no robots.txt (404 -> fetch allowed)

Stdlib only. Run: python3 test-servers.py  (blocks until killed)
"""
import http.server
import json
import os
import threading

BASE = os.path.dirname(os.path.abspath(__file__))
HITS_FILE = os.path.join(BASE, "canary-hits.jsonl")


class CanaryHandler(http.server.BaseHTTPRequestHandler):
    def _handle(self):
        hit = {"path": self.path, "headers": dict(self.headers)}
        with open(HITS_FILE, "a") as f:
            f.write(json.dumps(hit) + "\n")
        body = b"canary-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle

    def log_message(self, *a):
        pass


class RedirectorHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # 302 to the loopback canary: the SSRF-via-redirect proof of concept.
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:8898/canary-hit")
        self.end_headers()

    def log_message(self, *a):
        pass


class RobotsDenyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/secret-page":
            body = b"<html><body><p>TOP-SECRET-DENY-MARKER</p></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


class HonestHandler(http.server.BaseHTTPRequestHandler):
    PAGE = (
        b"<html><head><title>SkillProof honest page</title></head>"
        b"<body><article><h1>Honest content</h1>"
        b"<p>The quick brown fox jumps over the lazy dog. " * 40
        + b"</p></article></body></html>"
    )

    def do_GET(self):
        if self.path == "/page":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(self.PAGE)))
            self.end_headers()
            self.wfile.write(self.PAGE)
        else:
            # no robots.txt anywhere: 404 -> fetch allowed per server logic
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


def serve(port, handler):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


if __name__ == "__main__":
    if os.path.exists(HITS_FILE):
        os.remove(HITS_FILE)
    serve(8898, CanaryHandler)
    serve(8899, RedirectorHandler)
    serve(8900, RobotsDenyHandler)
    serve(8901, HonestHandler)
    print("test servers up: 8898=canary 8899=redirector 8900=robots-deny 8901=honest", flush=True)
    threading.Event().wait()
