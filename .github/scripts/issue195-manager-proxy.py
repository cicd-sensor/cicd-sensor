#!/usr/bin/env python3
"""Loopback-only fault injector. Never log headers or request/response bodies."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

UPSTREAM = "cicd-sensor-manager-c5bmuzncpq-an.a.run.app"
ALLOWED = {"/cicd_sensor.manager.v1beta1.ConfigService/FetchConfig",
           "/cicd_sensor.manager.v1beta1.CollectorService/IngestLog"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        if self.path not in ALLOWED:
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > 32 * 1024 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        if self.path.endswith("/IngestLog") and Path("/run/issue195/manager-503").exists():
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"code":"unavailable","message":"issue195 injected fault"}')
            print("injected_ingest_503", flush=True)
            return
        conn = http.client.HTTPSConnection(UPSTREAM, timeout=15)
        try:
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in {"host", "connection", "transfer-encoding"}}
            conn.request("POST", self.path, body=body, headers=headers)
            response = conn.getresponse()
            result = response.read()
            self.send_response(response.status)
            for key in ("Content-Type", "Content-Encoding"):
                if response.getheader(key):
                    self.send_header(key, response.getheader(key))
            self.send_header("Content-Length", str(len(result)))
            self.end_headers()
            self.wfile.write(result)
            print(self.path.rsplit("/", 1)[-1], response.status, flush=True)
        except (OSError, http.client.HTTPException):
            self.send_error(502)
        finally:
            conn.close()


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 19580), Handler).serve_forever()
