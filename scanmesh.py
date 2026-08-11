#!/usr/bin/env python3
"""ScanMesh - rule-based security-tool orchestrator (MVP slice).

Runs nmap, normalizes output to a common finding schema, de-duplicates /
correlates across tools, renders one HTML report. No Celery/Redis/Postgres/
Docker/FastAPI - those are added only when concurrent long-running scans on a
real engagement actually demand them.

Connectors (all normalize to one Finding schema):
    nmap      subprocess + XML   (tested live)
    sqlmap    subprocess + log   (parser tested offline; needs sqlmap installed)
    tshark    subprocess + pcap  (evidence, not findings; needs Wireshark)
    acunetix  REST               (UNTESTED - needs licensed instance + API key)
    burp      REST               (UNTESTED - needs Pro/Enterprise REST API)

Usage:
    python scanmesh.py <target>          # live nmap scan -> report.html
    python scanmesh.py --demo            # run self-check on sample data
    python scanmesh.py --self-check      # alias for --demo

Authorized use only: point this at hosts you own or have written permission
to test.
"""
from __future__ import annotations

import glob
import html
import os
import re
import subprocess
import sys
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

# --- severity normalization (Section 6.3): each tool's labels -> common scale
SEV_ORDER = ["info", "low", "medium", "high", "critical"]
SEV_MAP = {
    # nmap has no severity; open ports are info unless a rule bumps them
    "open": "info",
    # acunetix / burp style labels, mapped for when those connectors land
    "informational": "info", "information": "info",
    "low": "low", "medium": "medium", "high": "high",
    "critical": "critical",
}


def norm_sev(label: str) -> str:
    return SEV_MAP.get((label or "").strip().lower(), "info")


@dataclass
class Finding:
    tool: str
    target: str
    finding_type: str
    severity: str = "info"
    evidence: str = ""
    port: int | None = None
    service: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tools: set[str] = field(default_factory=set)

    def __post_init__(self):
        self.severity = norm_sev(self.severity)
        self.tools.add(self.tool)


# --- 5.1 Nmap connector -------------------------------------------------------
def run_nmap(target: str, extra_args: list[str] | None = None) -> str:
    """Run nmap with XML output to stdout. Returns the XML text."""
    args = ["nmap", "-oX", "-", *(extra_args or ["-T4", "-F"]), target]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"nmap failed: {proc.stderr.strip() or proc.returncode}")
    return proc.stdout


def parse_nmap_xml(xml_text: str) -> list[Finding]:
    """Parse nmap XML into findings (one per open port)."""
    root = ET.fromstring(xml_text)
    findings: list[Finding] = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        host_ip = addr_el.get("addr") if addr_el is not None else "unknown"
        os_el = host.find("./os/osmatch")
        os_guess = os_el.get("name") if os_el is not None else ""
        for port in host.findall("./ports/port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = int(port.get("portid"))
            svc_el = port.find("service")
            service = svc_el.get("name") if svc_el is not None else ""
            evidence = f"port {portid}/{port.get('protocol')} open"
            if os_guess:
                evidence += f"; os guess: {os_guess}"
            findings.append(Finding(
                tool="nmap", target=host_ip,
                finding_type=f"Open Port: {service or portid}",
                severity="open", evidence=evidence,
                port=portid, service=service,
            ))
    return findings


# --- 5.4 sqlmap connector -----------------------------------------------------
def run_sqlmap(url: str, out_dir: str, extra_args: list[str] | None = None) -> str:
    """Run sqlmap non-interactively against one URL. Returns its log text.
    Only ever call this on injection points already flagged by another tool
    (Section 5.4) - not a blind sweep.

    The sqlmap command defaults to `sqlmap` (a real binary on PATH, e.g. Linux);
    override via SCANMESH_SQLMAP for other layouts, e.g. on Windows where it's a
    script: set SCANMESH_SQLMAP=python D:\\SecTools\\sqlmap\\sqlmap.py"""
    import shlex
    cmd = os.environ.get("SCANMESH_SQLMAP", "sqlmap")
    base = shlex.split(cmd, posix=(os.name != "nt"))
    args = [*base, "-u", url, "--batch", f"--output-dir={out_dir}",
            *(extra_args or [])]
    subprocess.run(args, capture_output=True, text=True)
    logs = glob.glob(os.path.join(out_dir, "**", "log"), recursive=True)
    return "\n".join(open(p, encoding="utf-8", errors="replace").read() for p in logs)


def parse_sqlmap_log(log_text: str, target: str) -> list[Finding]:
    """Pure parser over sqlmap's log/stdout. One finding per vulnerable param."""
    findings: list[Finding] = []
    for m in re.finditer(
        r"Parameter:\s*(?P<param>\S+)\s*\((?P<place>\w+)\).*?"
        r"Type:\s*(?P<type>[^\n]+)",
        log_text, re.DOTALL,
    ):
        findings.append(Finding(
            tool="sqlmap", target=target, finding_type="SQL Injection",
            severity="critical",
            evidence=f"param {m['param']} ({m['place']}) - {m['type'].strip()}",
        ))
    return findings


# --- 5.5 Wireshark/tshark connector (evidence, not findings) ------------------
def capture_start(iface: str, pcap_path: str) -> subprocess.Popen:
    """Start a background tshark capture. Stop with proc.terminate()."""
    return subprocess.Popen(["tshark", "-i", iface, "-w", pcap_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def tshark_fields(pcap_path: str) -> str:
    """Extract a tab-separated packet summary from a pcap."""
    proc = subprocess.run(
        ["tshark", "-r", pcap_path, "-T", "fields",
         "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol",
         "-e", "_ws.col.Info", "-E", "separator=\t"],
        capture_output=True, text=True)
    return proc.stdout


def parse_tshark_evidence(fields_text: str, target: str, limit: int = 20) -> str:
    """Pure parser: keep packet lines touching `target`, as an evidence blob."""
    lines = [ln for ln in fields_text.splitlines()
             if target in ln.split("\t", 2)[:2]]
    return "; ".join(ln.replace("\t", " ") for ln in lines[:limit])


# --- 5.2 Acunetix connector (REST) - UNTESTED, needs license ------------------
_AX_SEV = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def parse_acunetix_vulns(payload: dict) -> list[Finding]:
    """Pure parser over Acunetix `.../vulnerabilities` JSON."""
    findings = []
    for v in payload.get("vulnerabilities", []):
        sev = v.get("severity")
        findings.append(Finding(
            tool="acunetix",
            target=v.get("affected_url") or v.get("target", ""),
            finding_type=v.get("vt_name") or v.get("vuln_type", "Unknown"),
            severity=_AX_SEV.get(sev, str(sev or "info")),
            evidence=(v.get("description") or "")[:500],
        ))
    return findings


def acunetix_scan(base_url: str, api_key: str, target: str,
                  timeout: int = 3600) -> list[Finding]:  # pragma: no cover
    """POST target -> start scan -> poll -> fetch vulns. Untested end to end;
    verify against your Acunetix version's actual API before relying on it."""
    import time
    import requests
    h = {"X-Auth": api_key, "Content-Type": "application/json"}
    s = requests.Session(); s.headers.update(h); s.verify = False
    tid = s.post(f"{base_url}/api/v1/targets",
                 json={"address": target, "description": "scanmesh"}
                 ).json()["target_id"]
    sid = s.post(f"{base_url}/api/v1/scans",
                 json={"target_id": tid, "profile_id": "11111111-1111-1111-1111-111111111111"}
                 ).json()["scan_id"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        sc = s.get(f"{base_url}/api/v1/scans/{sid}").json()
        if sc["current_session"]["status"] in ("completed", "failed"):
            break
        time.sleep(15)
    vulns = s.get(f"{base_url}/api/v1/scans/{sid}/results/last/vulnerabilities").json()
    return parse_acunetix_vulns(vulns)


# --- 5.3 Burp connector (REST) - UNTESTED, needs Pro/Enterprise ---------------
def parse_burp_issues(payload: dict) -> list[Finding]:
    """Pure parser over burp-rest-api scan JSON (issue_events / issues)."""
    issues = payload.get("issues")
    if issues is None:
        issues = [e.get("issue", e) for e in payload.get("issue_events", [])]
    findings = []
    for i in issues:
        origin = i.get("origin", "") + i.get("path", "")
        findings.append(Finding(
            tool="burp",
            target=origin or i.get("host", ""),
            finding_type=i.get("name", "Unknown"),
            severity=i.get("severity", "info"),
            evidence=(i.get("issueBackground") or i.get("description") or "")[:500],
        ))
    return findings


def burp_scan(base_url: str, target: str,
              timeout: int = 3600) -> list[Finding]:  # pragma: no cover
    """Submit scan -> poll -> pull issues. Untested; confirm your burp-rest-api
    endpoint shape (Community Edition has no REST API at all)."""
    import time
    import requests
    s = requests.Session()
    loc = s.post(f"{base_url}/v0.1/scan", json={"urls": [target]}).headers["Location"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        sc = s.get(f"{base_url}/v0.1/scan/{loc}").json()
        if sc.get("scan_status") in ("succeeded", "failed"):
            return parse_burp_issues(sc)
        time.sleep(15)
    return []


# --- 5.6 OWASP ZAP connector (REST) - FREE drop-in for Acunetix/Burp ----------
_ZAP_SEV = {"informational": "info", "low": "low",
            "medium": "medium", "high": "high"}


def parse_zap_alerts(payload: dict) -> list[Finding]:
    """Pure parser over ZAP `/JSON/core/view/alerts` JSON."""
    findings = []
    for a in payload.get("alerts", []):
        findings.append(Finding(
            tool="zap",
            target=a.get("url", ""),
            finding_type=a.get("name", "Unknown"),
            severity=_ZAP_SEV.get((a.get("risk") or "").lower(), "info"),
            evidence=(a.get("description") or "")[:500],
        ))
    return findings


def zap_scan(url: str, api_key: str, base: str = "http://localhost:8080",
             timeout: int = 3600) -> list[Finding]:  # pragma: no cover
    """Spider -> active scan -> pull alerts, via ZAP's REST API. Tested against
    ZAP daemon (`zap.sh -daemon -config api.key=<key>`); no license needed."""
    import time
    import requests
    s = requests.Session()

    def call(path, **params):
        params["apikey"] = api_key
        return s.get(f"{base}{path}", params=params).json()

    def wait(view, scan_id):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if int(call(f"/JSON/{view}/view/status/", scanId=scan_id)["status"]) >= 100:
                return
            time.sleep(5)

    wait("spider", call("/JSON/spider/action/scan/", url=url)["scan"])
    wait("ascan", call("/JSON/ascan/action/scan/", url=url)["scan"])
    # ZAP `baseurl` is a prefix match; injected payloads change the query, so
    # filter on the path without the query or we drop the injection alerts.
    base_target = url.split("?", 1)[0]
    return parse_zap_alerts(call("/JSON/core/view/alerts/", baseurl=base_target))


# --- 6.1 Rule engine: what to run next given nmap results ----------------------
WEB_PORTS = {80, 443, 8080, 8000, 8443}


def next_steps(findings: list[Finding]) -> list[str]:
    """Rule-based trigger logic (Section 2/6.1). Returns advisory next actions;
    it does NOT auto-run offensive tools - the operator does that."""
    steps: list[str] = []
    web_targets = sorted({f.target for f in findings
                          if f.tool == "nmap" and f.port in WEB_PORTS})
    for t in web_targets:
        steps.append(f"Web port open on {t} -> queue Acunetix/Burp scan (manual)")
    # web-scanner injection hits -> targeted sqlmap (Section 5.4)
    inj = sorted({f.target for f in findings
                  if f.tool in ("acunetix", "burp", "zap")
                  and "sql" in f.finding_type.lower()})
    for t in inj:
        steps.append(f"Injection flagged on {t} -> run sqlmap on that param (manual)")
    return steps


# --- 6.2 / 7 De-dup + correlation --------------------------------------------
# Canonical vuln families so different tools' labels for the same bug merge.
_CANON_TYPES = (
    ("sql injection", "SQL Injection"),
    ("cross-site scripting", "Cross-Site Scripting"),
    ("cross site scripting", "Cross-Site Scripting"),
    ("xss", "Cross-Site Scripting"),
)


def _canon_type(t: str) -> str:
    tl = t.lower()
    for needle, name in _CANON_TYPES:
        if needle in tl:
            return name
    return t


def _endpoint(target: str) -> str:
    """host+path without the query, so ?cat=1 and ?cat=%3B collapse to one."""
    p = urllib.parse.urlsplit(target)
    return f"{p.scheme}://{p.netloc}{p.path}" if p.scheme else target


def correlate(findings: list[Finding]) -> list[Finding]:
    """Merge findings for the same vuln family on the same endpoint into one
    record, keeping the highest severity and unioning contributing tools.
    Different tools name the same bug differently (e.g. 'SQL Injection' vs
    'SQL Injection - SQLite') and hit different query values - both normalized."""
    merged: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (_endpoint(f.target), _canon_type(f.finding_type))
        if key not in merged:
            f.finding_type = _canon_type(f.finding_type)  # clean display label
            merged[key] = f
            continue
        m = merged[key]
        m.tools |= f.tools
        if SEV_ORDER.index(f.severity) > SEV_ORDER.index(m.severity):
            m.severity = f.severity
        if f.evidence and f.evidence not in m.evidence:
            m.evidence += f" | {f.evidence}"
    return list(merged.values())


# --- 7 / report ---------------------------------------------------------------
def render_report(findings: list[Finding], target: str, steps: list[str]) -> str:
    rows = sorted(findings, key=lambda f: -SEV_ORDER.index(f.severity))
    body = "\n".join(
        f"<tr class='sev-{f.severity}'><td>{html.escape(f.severity)}</td>"
        f"<td>{html.escape(f.target)}</td>"
        f"<td>{html.escape(f.finding_type)}</td>"
        f"<td>{html.escape(', '.join(sorted(f.tools)))}</td>"
        f"<td>{html.escape(f.evidence)}</td></tr>"
        for f in rows
    )
    steps_html = "".join(f"<li>{html.escape(s)}</li>" for s in steps) or "<li>none</li>"
    counts = {s: sum(1 for f in findings if f.severity == s) for s in reversed(SEV_ORDER)}
    summary = ", ".join(f"{k}: {v}" for k, v in counts.items() if v)
    return f"""<!doctype html><meta charset=utf-8>
<title>ScanMesh Report - {html.escape(target)}</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;max-width:60rem}}
 table{{border-collapse:collapse;width:100%}}
 th,td{{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;vertical-align:top}}
 th{{background:#f4f4f4}}
 .sev-critical{{background:#fde}} .sev-high{{background:#fee}}
 .sev-medium{{background:#ffeede}} .sev-low{{background:#f6f6f6}}
</style>
<h1>ScanMesh Report</h1>
<p><b>Target:</b> {html.escape(target)} &nbsp; <b>Generated:</b> {datetime.now().isoformat(timespec='seconds')}</p>
<p><b>Summary:</b> {summary or 'no findings'}</p>
<h2>Findings ({len(findings)})</h2>
<table><tr><th>Severity</th><th>Target</th><th>Type</th><th>Tools</th><th>Evidence</th></tr>
{body}</table>
<h2>Suggested next steps (operator-run)</h2><ul>{steps_html}</ul>
"""


def scan(target: str) -> list[Finding]:
    findings = parse_nmap_xml(run_nmap(target))
    return correlate(findings)


# --- self-check (ponytail: one runnable check on the non-trivial logic) -------
SAMPLE_XML = """<?xml version="1.0"?><nmaprun>
<host><address addr="10.0.0.5" addrtype="ipv4"/>
<ports>
 <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
 <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
 <port protocol="tcp" portid="139"><state state="closed"/></port>
</ports>
<os><osmatch name="Linux 5.x"/></os></host></nmaprun>"""


def demo() -> None:
    f = parse_nmap_xml(SAMPLE_XML)
    assert len(f) == 2, f"expected 2 open ports, got {len(f)}"
    assert all(x.severity == "info" for x in f), "nmap ports should normalize to info"
    assert {x.port for x in f} == {80, 22}, "closed port 139 should be dropped"

    # correlation merges a duplicate finding_type from another tool
    dup = Finding(tool="burp", target="10.0.0.5",
                  finding_type="Open Port: http", severity="high",
                  evidence="server banner leak")
    merged = correlate(f + [dup])
    http = next(m for m in merged if m.finding_type == "Open Port: http")
    assert http.tools == {"nmap", "burp"}, f"tools not unioned: {http.tools}"
    assert http.severity == "high", "merged severity should take the max"
    assert len(merged) == 2, "http findings should collapse to one row"

    steps = next_steps(f)
    assert any("10.0.0.5" in s for s in steps), "web-port trigger rule missed :80"

    # cross-tool merge: same vuln family, different labels AND query values
    mix = [Finding("sqlmap", "http://h/x?id=1", "SQL Injection", "critical", "p1"),
           Finding("zap", "http://h/x?id=%3B", "SQL Injection - SQLite", "high", "p2")]
    mm = correlate(mix)
    assert len(mm) == 1, f"SQLi variants should merge, got {len(mm)}"
    assert mm[0].tools == {"sqlmap", "zap"}, "merge should union tools"
    assert mm[0].severity == "critical", "merge should keep max severity"
    assert mm[0].finding_type == "SQL Injection", "merge should canonicalize label"

    # sqlmap parser
    sm_log = ("sqlmap identified the following injection point(s):\n"
              "Parameter: id (GET)\n    Type: boolean-based blind\n"
              "    Title: AND boolean-based blind\n")
    sm = parse_sqlmap_log(sm_log, "http://10.0.0.5/x?id=1")
    assert len(sm) == 1 and sm[0].severity == "critical", "sqlmap parse failed"
    assert "id (GET)" in sm[0].evidence

    # acunetix parser (numeric severity -> label)
    ax = parse_acunetix_vulns({"vulnerabilities": [
        {"severity": 4, "vt_name": "SQL Injection",
         "affected_url": "http://10.0.0.5/x", "description": "blind sqli"}]})
    assert ax[0].severity == "critical" and ax[0].tool == "acunetix"

    # burp parser (issues + issue_events shapes)
    bp = parse_burp_issues({"issues": [
        {"name": "SQL injection", "severity": "high",
         "origin": "http://10.0.0.5", "path": "/x", "description": "d"}]})
    assert bp[0].finding_type == "SQL injection" and bp[0].severity == "high"
    assert parse_burp_issues({"issue_events": [{"issue": {"name": "XSS",
        "severity": "medium", "host": "h"}}]})[0].finding_type == "XSS"

    # sqlmap trigger rule fires off a burp injection finding
    assert any("sqlmap" in s for s in next_steps(bp)), "sqlmap trigger missed"

    # zap parser (free Acunetix/Burp replacement)
    zp = parse_zap_alerts({"alerts": [
        {"risk": "High", "name": "SQL Injection",
         "url": "http://10.0.0.5/x?id=1", "description": "sqli"}]})
    assert zp[0].severity == "high" and zp[0].tool == "zap"
    assert any("sqlmap" in s for s in next_steps(zp)), "zap->sqlmap trigger missed"

    # tshark evidence parser (pure, on sample field text)
    ev = parse_tshark_evidence(
        "10.0.0.5\t10.0.0.9\tHTTP\tGET /x\n8.8.8.8\t1.1.1.1\tDNS\tq", "10.0.0.5")
    assert "GET /x" in ev and "DNS" not in ev, "tshark evidence filter failed"

    assert "10.0.0.5" in render_report(merged, "10.0.0.5", steps)
    print("self-check OK")


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("--demo", "--self-check"):
        demo()
        return 0
    if argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    target = argv[0]
    findings = scan(target)
    steps = next_steps(findings)
    out = "report.html"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(render_report(findings, target, steps))
    print(f"{len(findings)} finding(s) -> {out}")
    for s in steps:
        print("  next:", s)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
