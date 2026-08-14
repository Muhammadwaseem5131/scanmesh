#!/usr/bin/env python3
"""ScanMesh web UI + persistence (stdlib only).

A single-file local dashboard: submit a target, a scan runs in a background
thread, findings are stored in SQLite, and the correlated report is viewable
in the browser. No FastAPI/Celery/Redis/Postgres.

    python web.py            # serve on http://127.0.0.1:8000

DB: scanmesh.db (SQLite)
    scans(id, target, kind, status, created)      -- one row per scan run
    findings(id, scan_id, tool, target, ..., tools) -- correlated results
"""
from __future__ import annotations

import html
import os
import sqlite3
import subprocess
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import scanmesh as sm

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanmesh.db")
ZAP_BASE = os.environ.get("SCANMESH_ZAP", "http://127.0.0.1:8090")
ZAP_KEY = os.environ.get("SCANMESH_ZAP_KEY", "scanmesh123")
# optional: set to a tshark interface (e.g. "\Device\NPF_Loopback") to attach
# packet-capture evidence to web scans; unset = skip capture (default).
CAPTURE_IFACE = os.environ.get("SCANMESH_CAPTURE_IFACE")


def db() -> sqlite3.Connection:
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY, target TEXT, kind TEXT,
        status TEXT, created TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS findings(
        id INTEGER PRIMARY KEY, scan_id INTEGER, tool TEXT, target TEXT,
        finding_type TEXT, severity TEXT, evidence TEXT, tools TEXT)""")
    return c


def _host(target: str) -> str:
    p = urllib.parse.urlsplit(target if "://" in target else "//" + target)
    return p.hostname or target


def _url(target: str) -> str:
    return target if "://" in target else "http://" + target


def _benign_url(url: str) -> str:
    """Reset query values to a benign '1' so sqlmap gets a working baseline.
    A web scanner reports injection against its payload URL (e.g. ?cat=%3B),
    which returns a 500 error page - feeding that to sqlmap breaks its
    baseline comparison. Keep the params, drop the payloads."""
    p = urllib.parse.urlsplit(url)
    q = [(k, "1") for k, _ in urllib.parse.parse_qsl(p.query, keep_blank_values=True)]
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path,
                                    urllib.parse.urlencode(q), ""))


LOOPBACK = r"\Device\NPF_Loopback"


def _capture_iface(target: str) -> str | None:
    """Pick the tshark interface for a target: explicit env override, else
    loopback for local targets, else auto-detect the default-route adapter."""
    if CAPTURE_IFACE:
        return CAPTURE_IFACE
    if _host(target) in ("127.0.0.1", "localhost", "::1"):
        return LOOPBACK
    try:  # Windows/Npcap: GUID of the adapter carrying the default route
        ps = ("$i=(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | "
              "Sort-Object RouteMetric | Select-Object -First 1).ifIndex;"
              "(Get-NetAdapter -InterfaceIndex $i).InterfaceGuid")
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=15).stdout.strip()
        return rf"\Device\NPF_{out}" if out.startswith("{") else None
    except Exception:
        return None


# --- the scan pipeline, run off-thread so the HTTP request returns at once ---
def run_scan(scan_id: int, target: str, kind: str) -> None:
    findings: list[sm.Finding] = []
    notes = []
    host = _host(target)
    outdir = os.path.join(os.path.dirname(DB), "sqlmap_out")
    # tshark capture spans the whole scan window; every scan attempts it
    iface = _capture_iface(target)
    cap = pcap = None
    if iface:
        pcap = os.path.join(os.path.dirname(DB), f"cap_{scan_id}.pcap")
        try:
            cap = sm.capture_start(iface, pcap)
        except Exception as e:
            notes.append(f"capture start: {e}")
    try:
        findings += sm.parse_nmap_xml(sm.run_nmap(host))

        if kind == "web":
            try:
                zf = sm.zap_scan(_url(target), ZAP_KEY, base=ZAP_BASE)
                findings += zf
            except Exception as e:  # ZAP daemon down
                zf = []
                notes.append(f"zap: {e}")

            # sqlmap ALWAYS runs: the target's own params + anything ZAP flagged
            endpoints = []
            tgt = _benign_url(_url(target))
            if urllib.parse.urlsplit(tgt).query:
                endpoints.append(tgt)
            for f in zf:
                if "sql" in f.finding_type.lower():
                    b = _benign_url(f.target)
                    if b not in endpoints:
                        endpoints.append(b)
            hits = 0
            for u in endpoints:
                try:
                    sf = sm.parse_sqlmap_log(sm.run_sqlmap(u, outdir), u)
                    findings += sf
                    hits += len(sf)
                except Exception as e:
                    notes.append(f"sqlmap: {e}")
            # leave a sqlmap row even when nothing is vulnerable (not canonicalized)
            if hits == 0:
                if endpoints:
                    findings.append(sm.Finding("sqlmap", host,
                        "SQLi Test - not vulnerable", "info",
                        f"sqlmap tested {len(endpoints)} parameterized URL(s); no injection found"))
                else:
                    findings.append(sm.Finding("sqlmap", host,
                        "SQLi Test - skipped", "info",
                        "no URL parameters to test on this target"))

        # stop capture and ALWAYS record a tshark row
        npkts = 0
        if cap:
            cap.terminate()
            time.sleep(1)
            cap = None
            try:
                fields = sm.tshark_fields(pcap)
                npkts = len(fields.splitlines())
                ev = sm.parse_tshark_evidence(fields, host)
            except Exception as e:
                ev = ""
                notes.append(f"tshark: {e}")
            if ev:
                findings.append(sm.Finding("tshark", host,
                    "Traffic Evidence", "info", ev[:1000]))
            else:
                findings.append(sm.Finding("tshark", host,
                    "Traffic Capture - no matching packets", "info",
                    f"captured {npkts} pkt(s) on {iface}; none matched {host}. "
                    "Set SCANMESH_CAPTURE_IFACE to the adapter carrying this traffic."))
        else:
            findings.append(sm.Finding("tshark", host,
                "Traffic Capture - unavailable", "info",
                "capture did not start (interface/permission); "
                "run as Administrator or set SCANMESH_CAPTURE_IFACE."))

        findings = sm.correlate(findings)
        status = "done" + (f" ({'; '.join(notes)})" if notes else "")
    except Exception as e:
        status = f"error: {e}"
    finally:
        if cap:
            cap.terminate()

    c = db()
    for f in findings:
        c.execute("""INSERT INTO findings(scan_id,tool,target,finding_type,
            severity,evidence,tools) VALUES(?,?,?,?,?,?,?)""",
            (scan_id, f.tool, f.target, f.finding_type, f.severity,
             f.evidence, ",".join(sorted(f.tools))))
    c.execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))
    c.commit()
    c.close()


def _load_findings(scan_id: int) -> list[sm.Finding]:
    c = db()
    rows = c.execute("""SELECT tool,target,finding_type,severity,evidence,tools
        FROM findings WHERE scan_id=?""", (scan_id,)).fetchall()
    c.close()
    out = []
    for tool, target, ftype, sev, ev, tools in rows:
        f = sm.Finding(tool=tool, target=target, finding_type=ftype,
                       severity=sev, evidence=ev)
        f.tools = set(tools.split(",")) if tools else {tool}
        out.append(f)
    return out


# --- HTML -------------------------------------------------------------------
INDEX_CSS = """<style>
 body{font:14px/1.5 system-ui,sans-serif;margin:2rem;max-width:60rem}
 h1{margin-bottom:.2rem} form{margin:1rem 0;padding:1rem;background:#f6f6f6;border-radius:8px}
 input,select,button{font:inherit;padding:.4rem}
 input[name=target]{width:22rem}
 table{border-collapse:collapse;width:100%;margin-top:1rem}
 th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}
 th{background:#f4f4f4} .running{color:#b60} .done{color:#161}
 a{color:#06c}
</style>"""


def index_page() -> bytes:
    c = db()
    rows = c.execute("""SELECT id,target,kind,status,created FROM scans
        ORDER BY id DESC LIMIT 100""").fetchall()
    c.close()
    trs = "".join(
        f"<tr><td>{i}</td><td>{html.escape(t)}</td><td>{html.escape(k)}</td>"
        f"<td class='{'running' if st=='running' else 'done'}'>{html.escape(st)}</td>"
        f"<td>{html.escape(cr)}</td>"
        f"<td><a href='/scan?id={i}'>report</a></td></tr>"
        for i, t, k, st, cr in rows) or "<tr><td colspan=6>no scans yet</td></tr>"
    # auto-refresh only while something is running, so the demo updates itself
    refresh = "<meta http-equiv=refresh content=4>" if any(
        r[3] == "running" for r in rows) else ""
    page = f"""<!doctype html><meta charset=utf-8><title>ScanMesh</title>{refresh}{INDEX_CSS}
<h1>ScanMesh</h1><p>Authorized targets only.</p>
<form method=post action=/scan>
 <input name=target placeholder="192.168.1.10  or  http://host/path" required>
 <select name=kind>
   <option value=nmap>Port scan (nmap)</option>
   <option value=web>Web scan (nmap + ZAP + sqlmap)</option>
 </select>
 <button>Scan</button>
 <span style="color:#888">web scan needs the ZAP daemon running</span>
</form>
<table><tr><th>#</th><th>Target</th><th>Kind</th><th>Status</th><th>Created</th><th></th></tr>
{trs}</table>
<p style="color:#888">Refresh to update running scans.</p>"""
    return page.encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body: bytes, code=200, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/":
            self._send(index_page())
        elif u.path == "/scan":
            raw = urllib.parse.parse_qs(u.query).get("id", ["0"])[0]
            if not raw.isdigit():
                return self._send(b"bad scan id", 400)
            sid = int(raw)
            c = db()
            row = c.execute("SELECT target FROM scans WHERE id=?", (sid,)).fetchone()
            c.close()
            label = f"{row[0]} (scan #{sid})" if row else f"scan #{sid}"
            findings = _load_findings(sid)
            steps = sm.next_steps(findings)
            self._send(sm.render_report(findings, label, steps).encode())
        else:
            self._send(b"not found", 404)

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path != "/scan":
            return self._send(b"not found", 404)
        n = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(n).decode())
        target = form.get("target", [""])[0].strip()
        kind = form.get("kind", ["nmap"])[0]
        if not target:
            return self._send(b"target required", 400)
        c = db()
        cur = c.execute("INSERT INTO scans(target,kind,status,created) VALUES(?,?,?,?)",
                        (target, kind, "running",
                         datetime.now(timezone.utc).isoformat(timespec="seconds")))
        c.commit()
        sid = cur.lastrowid
        c.close()
        threading.Thread(target=run_scan, args=(sid, target, kind), daemon=True).start()
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()


def _check() -> None:
    assert _host("http://1.2.3.4:80/x?a=1") == "1.2.3.4"
    assert _host("1.2.3.4") == "1.2.3.4"
    assert _url("1.2.3.4") == "http://1.2.3.4"
    assert _url("https://h/x") == "https://h/x"
    # payload URL -> benign baseline, params kept, values reset
    assert _benign_url("http://h/p?cat=%3B&id=DROP") == "http://h/p?cat=1&id=1"
    assert _benign_url("http://h/p") == "http://h/p"
    # the "not vulnerable" sqlmap note must NOT be canonicalized into a real
    # SQL Injection finding (that would read as a vuln that isn't there)
    nv = sm.correlate([sm.Finding("sqlmap", "h", "SQLi Test - not vulnerable",
                                  "info", "x")])
    assert nv[0].finding_type == "SQLi Test - not vulnerable", nv[0].finding_type
    print("web self-check OK")


if __name__ == "__main__":
    import sys
    if "--check" in sys.argv:
        _check()
    else:
        db().close()  # ensure tables exist
        print("ScanMesh UI -> http://127.0.0.1:8000  (Ctrl+C to stop)")
        ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
