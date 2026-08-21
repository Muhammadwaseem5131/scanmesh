"""Integration tests: drive the real HTTP server end-to-end with the live
tools stubbed out, so the routes + run_scan orchestration are covered in CI
without nmap/ZAP/sqlmap/tshark installed."""
import http.server
import json
import os
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import scanmesh as sm
import web


def _post(base, path, **data):
    urllib.request.urlopen(base + path, data=urllib.parse.urlencode(data).encode()).read()


def _get(base, path):
    return urllib.request.urlopen(base + path).read().decode()


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setattr(web, "DB", str(tmp_path / "t.db"))
    monkeypatch.setattr(web, "_capture_iface", lambda target: None)  # skip tshark
    # stub the live tools -> no external binaries/network needed
    monkeypatch.setattr(web.sm, "run_nmap", lambda host, *a, **k: sm.SAMPLE_XML)
    monkeypatch.setattr(web.sm, "zap_scan", lambda *a, **k: [sm.Finding(
        "zap", "http://127.0.0.1:8099/products?cat=1", "SQL Injection", "high", "suspected")])
    monkeypatch.setattr(web.sm, "run_sqlmap",
        lambda url, out, *a, **k: "Parameter: cat (GET)\n    Type: boolean-based blind\n")
    web._reap_running()  # creates tables in the temp DB
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _wait_done(db, sid, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        row = sqlite3.connect(db).execute("SELECT status FROM scans WHERE id=?", (sid,)).fetchone()
        if row and row[0].startswith("done"):
            return
        time.sleep(0.1)
    raise AssertionError("scan never finished")


def test_full_web_scan_flow(server):
    assert "Scan console" in _get(server, "/")
    _post(server, "/scan", target="http://127.0.0.1:8099/products?cat=1", kind="web")
    _wait_done(web.DB, 1)

    rows = json.loads(_get(server, "/rows"))
    assert rows["running"] is False

    rep = _get(server, "/scan?id=1")
    assert "SQL Injection" in rep and "critical" in rep.lower()
    # merged from ZAP + sqlmap, and nmap ran too -> all three tools present
    for tool in ("nmap", "zap", "sqlmap"):
        assert tool in rep, f"{tool} missing from report"


def test_delete_removes_scan(server):
    _post(server, "/scan", target="127.0.0.1", kind="nmap")
    _wait_done(web.DB, 1)
    _post(server, "/delete", id="1")
    assert sqlite3.connect(web.DB).execute("SELECT count(*) FROM scans").fetchone()[0] == 0


def test_bad_scan_id_is_400_not_crash(server):
    with pytest.raises(urllib.error.HTTPError) as e:
        _get(server, "/scan?id=abc")
    assert e.value.code == 400


def test_reap_running_clears_stranded_scans(tmp_path, monkeypatch):
    monkeypatch.setattr(web, "DB", str(tmp_path / "r.db"))
    web._reap_running()  # create tables
    c = sqlite3.connect(web.DB)
    c.execute("INSERT INTO scans(target,kind,status,created) VALUES('x','web','running','t')")
    c.commit(); c.close()
    web._reap_running()  # simulate restart
    st = sqlite3.connect(web.DB).execute("SELECT status FROM scans").fetchone()[0]
    assert st.startswith("error: interrupted")
