#!/usr/bin/env python3
"""Tiny alert sink for the integration test: every POST body is appended, as one
JSON line, to the file given as argv[2]. Listens on 127.0.0.1:argv[1]."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT, OUT = int(sys.argv[1]), sys.argv[2]


class Sink(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            msg = json.loads(body)
        except ValueError:
            msg = {"raw": body.decode(errors="replace")}
        with open(OUT, "a") as f:
            f.write(json.dumps(msg) + "\n")
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", PORT), Sink).serve_forever()
