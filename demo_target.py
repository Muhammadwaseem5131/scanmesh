#!/usr/bin/env python3
"""Deliberately vulnerable demo target for ScanMesh (LOCALHOST ONLY).

A tiny app with a real SQL-injectable parameter, so you can demo the full
pipeline (nmap -> ZAP -> sqlmap) against something safe that you own.
Binds to 127.0.0.1 only. Do not expose this to a network.

    python demo_target.py            # serves http://127.0.0.1:8099/products?cat=1
"""
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = 8099
db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE products(id INT, name TEXT, cat INT)")
db.executemany("INSERT INTO products VALUES(?,?,?)",
               [(1, "widget", 1), (2, "gadget", 1), (3, "gizmo", 2)])
db.commit()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._html('<a href="/products?cat=1">products</a>')
            return
        if path != "/products":
            self.send_error(404)
            return
        cat = parse_qs(urlparse(self.path).query).get("cat", ["1"])[0]
        # VULNERABLE ON PURPOSE: raw string concat, no parameterization.
        sql = "SELECT id,name FROM products WHERE cat = " + cat
        try:
            rows = db.execute(sql).fetchall()
            self._html("".join(f"<li>{r[0]}:{r[1]}</li>" for r in rows))
        except Exception as e:
            self._html(f"<p>SQL error: {e}</p>", code=500)

    def _html(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(f"<html><ul>{body}</ul></html>".encode())


if __name__ == "__main__":
    print(f"Demo target -> http://127.0.0.1:{PORT}/products?cat=1  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
