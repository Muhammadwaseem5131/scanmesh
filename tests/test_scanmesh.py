"""Unit tests for the pure logic in scanmesh.py and web.py.

Parsers, correlation, severity normalization and the web helpers are all
pure functions - no external tools, no network - so they run anywhere
(including CI). The live connectors (nmap/ZAP/sqlmap/tshark) are exercised
by the end-to-end runs documented in the README, not here.

    pytest            # from the repo root
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scanmesh as sm
import web


# --- severity normalization -------------------------------------------------
def test_norm_sev_maps_and_defaults():
    assert sm.norm_sev("High") == "high"
    assert sm.norm_sev("informational") == "info"
    assert sm.norm_sev("open") == "info"
    assert sm.norm_sev("nonsense") == "info"  # unknown -> info


# --- nmap parser ------------------------------------------------------------
def test_parse_nmap_xml_open_ports_only():
    f = sm.parse_nmap_xml(sm.SAMPLE_XML)
    assert {x.port for x in f} == {80, 22}      # closed 139 dropped
    assert all(x.severity == "info" for x in f)
    assert all(x.tool == "nmap" for x in f)


# --- sqlmap parser ----------------------------------------------------------
def test_parse_sqlmap_log():
    log = ("sqlmap identified the following injection point(s):\n"
           "Parameter: id (GET)\n    Type: boolean-based blind\n")
    f = sm.parse_sqlmap_log(log, "http://h/x?id=1")
    assert len(f) == 1
    assert f[0].severity == "critical" and f[0].finding_type == "SQL Injection"


def test_parse_sqlmap_log_clean():
    assert sm.parse_sqlmap_log("no injection here", "http://h/x") == []


# --- ZAP / Acunetix / Burp parsers ------------------------------------------
def test_parse_zap_alerts():
    f = sm.parse_zap_alerts({"alerts": [
        {"risk": "High", "name": "SQL Injection", "url": "http://h/x", "description": "d"}]})
    assert f[0].severity == "high" and f[0].tool == "zap"


def test_parse_acunetix_numeric_severity():
    f = sm.parse_acunetix_vulns({"vulnerabilities": [
        {"severity": 4, "vt_name": "XSS", "affected_url": "http://h", "description": "d"}]})
    assert f[0].severity == "critical"


def test_parse_burp_both_shapes():
    a = sm.parse_burp_issues({"issues": [
        {"name": "SQLi", "severity": "high", "origin": "http://h", "path": "/x"}]})
    b = sm.parse_burp_issues({"issue_events": [
        {"issue": {"name": "XSS", "severity": "medium", "host": "h"}}]})
    assert a[0].severity == "high" and b[0].finding_type == "XSS"


# --- correlation ------------------------------------------------------------
def test_correlate_merges_same_endpoint_and_family():
    findings = [
        sm.Finding("sqlmap", "http://h/x?id=1", "SQL Injection", "critical", "p1"),
        sm.Finding("zap", "http://h/x?id=%3B", "SQL Injection - SQLite", "high", "p2"),
    ]
    merged = sm.correlate(findings)
    assert len(merged) == 1
    assert merged[0].tools == {"sqlmap", "zap"}
    assert merged[0].severity == "critical"          # keeps the max
    assert merged[0].finding_type == "SQL Injection"  # canonicalized


def test_correlate_keeps_distinct():
    findings = [
        sm.Finding("nmap", "10.0.0.5", "Open Port: http", "info", "80"),
        sm.Finding("nmap", "10.0.0.5", "Open Port: ssh", "info", "22"),
    ]
    assert len(sm.correlate(findings)) == 2


# --- rule engine ------------------------------------------------------------
def test_next_steps_triggers():
    web_port = sm.Finding("nmap", "10.0.0.5", "Open Port: http", "info", "", port=80)
    assert any("10.0.0.5" in s for s in sm.next_steps([web_port]))
    inj = sm.Finding("zap", "http://h/x", "SQL Injection", "high", "")
    assert any("sqlmap" in s for s in sm.next_steps([inj]))


# --- web helpers ------------------------------------------------------------
def test_benign_url_strips_payload():
    assert web._benign_url("http://h/p?cat=%3B&id=DROP") == "http://h/p?cat=1&id=1"
    assert web._benign_url("http://h/p") == "http://h/p"


def test_posture_verdict():
    assert web._posture({"critical": 1})[0] == "Critical exposure"
    assert web._posture({"high": 2})[0] == "Elevated risk"
    assert web._posture({"low": 1})[0] == "Low risk"
    assert web._posture({"info": 3})[0] == "Informational"
    assert web._posture({})[0] == "No findings"


def test_capture_iface_local_is_loopback():
    assert web._capture_iface("127.0.0.1") == web.LOOPBACK
    assert web._capture_iface("http://localhost:8099/x") == web.LOOPBACK


def test_status_cell_running_not_clickable_marker():
    assert "running" in web._status_cell("running")
    assert "error" in web._status_cell("error: boom")
