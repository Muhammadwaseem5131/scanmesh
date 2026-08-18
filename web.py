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

        if kind in ("web", "quick"):
            try:
                zf = sm.zap_scan(_url(target), ZAP_KEY, base=ZAP_BASE,
                                 quick=(kind == "quick"))
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


# --- HTML / design system ---------------------------------------------------
SEV_UI = ["critical", "high", "medium", "low", "info"]

SITE_CSS = """
:root{
  --bg:#f5f7fb; --bg2:#eef2f7; --panel:#ffffff; --panel2:#fbfcfe;
  --border:#e4e9f0; --border2:#d3dae4; --text:#101b2d; --muted:#57637a;
  --faint:#94a0b3; --accent:#0f766e; --accent-dim:#a7d8d0; --accent2:#2563eb;
  --crit:#d11e3a; --high:#c2540c; --med:#8f6a08; --low:#2563eb; --info:#5b6675;
  --crit-bg:#fdeaec; --high-bg:#fcecdd; --med-bg:#f7f0cf; --low-bg:#e7edfd; --info-bg:#eef1f6;
  --shadow:0 1px 2px rgba(16,24,40,.05),0 1px 3px rgba(16,24,40,.04);
  --radius:14px;
  --mono:"JetBrains Mono",ui-monospace,"Cascadia Code",Consolas,monospace;
  --sans:"Inter",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --display:"Space Grotesk","Inter",system-ui,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 var(--sans);
  background-image:radial-gradient(circle at 1px 1px,rgba(15,118,110,.05) 1px,transparent 0);
  background-size:26px 26px;-webkit-font-smoothing:antialiased;min-height:100vh}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1120px;margin:0 auto;padding:0 24px 72px}

/* header */
header{position:sticky;top:0;z-index:10;backdrop-filter:blur(10px);
  background:linear-gradient(180deg,rgba(245,247,251,.92),rgba(245,247,251,.72));
  border-bottom:1px solid var(--border)}
.hdr{max-width:1120px;margin:0 auto;padding:14px 24px;display:flex;align-items:center;gap:14px}
.mark{width:34px;height:34px;flex:none}
.brand{display:flex;flex-direction:column;line-height:1.1}
.brand b{font-size:19px;letter-spacing:.2px;font-family:var(--display);font-weight:700}
.brand span{font-size:11px;color:var(--muted);letter-spacing:.5px;text-transform:uppercase}
.hdr .spacer{flex:1}
.badge-auth{font:11px/1 var(--mono);color:var(--accent);border:1px solid var(--accent-dim);
  background:rgba(15,118,110,.06);padding:6px 10px;border-radius:999px;letter-spacing:.4px}

/* cards */
.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--border);
  border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)}
h1.page{font-size:26px;margin:28px 0 4px;letter-spacing:.2px;font-family:var(--display);font-weight:600}
.sub{color:var(--muted);font-size:13px;margin:0 0 20px}

/* scan form */
.scan-form{display:flex;flex-wrap:wrap;gap:12px;align-items:center}
.scan-form .field{flex:1;min-width:280px;display:flex;flex-direction:column;gap:6px}
label.lbl{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted)}
input[type=text]{width:100%;font:14px var(--mono);color:var(--text);background:var(--bg2);
  border:1px solid var(--border2);border-radius:10px;padding:12px 14px;outline:none;transition:border-color .15s,box-shadow .15s}
input[type=text]:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(15,118,110,.15)}
.seg{display:inline-flex;background:var(--bg2);border:1px solid var(--border2);border-radius:10px;padding:3px}
.seg input{position:absolute;opacity:0;pointer-events:none}
.seg label{font-size:13px;padding:9px 16px;border-radius:8px;cursor:pointer;color:var(--muted);
  transition:background .15s,color .15s;white-space:nowrap}
.seg input:checked+label{background:var(--accent);color:#fff;font-weight:600}
.seg input:focus-visible+label{outline:2px solid var(--accent);outline-offset:2px}
.btn{font:600 14px var(--sans);color:#fff;background:var(--accent);border:0;border-radius:10px;
  padding:12px 22px;cursor:pointer;transition:transform .12s,filter .15s}
.btn:hover{filter:brightness(1.08)}
.btn:active{transform:translateY(1px)}
.hint{color:var(--faint);font-size:12px;width:100%;margin-top:2px}

/* stat tiles */
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:20px 0}
.tile{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px 16px;position:relative;overflow:hidden}
.tile::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--c)}
.tile .num{font:700 26px/1 var(--mono);color:var(--text)}
.tile .lab{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-top:6px;display:flex;align-items:center;gap:6px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--c);flex:none;box-shadow:0 0 8px var(--c)}
.sev-critical{--c:var(--crit)} .sev-high{--c:var(--high)} .sev-medium{--c:var(--med)}
.sev-low{--c:var(--low)} .sev-info{--c:var(--info)}

/* severity distribution bar */
.dist{display:flex;height:10px;border-radius:6px;overflow:hidden;border:1px solid var(--border);margin:4px 0 22px}
.dist span{display:block}

/* table */
.tbl{width:100%;border-collapse:separate;border-spacing:0;margin-top:6px;font-size:14px}
.tbl th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);
  padding:10px 14px;border-bottom:1px solid var(--border)}
.tbl td{padding:13px 14px;border-bottom:1px solid var(--border)}
.tbl tr:last-child td{border-bottom:0}
.tbl tbody tr{transition:background .12s}
.tbl tbody tr:hover{background:rgba(15,118,110,.03)}
.mono{font-family:var(--mono);font-size:13px}
.t-id{color:var(--faint);font-family:var(--mono)}

/* pills + badges */
.pill{display:inline-flex;align-items:center;gap:6px;font:600 11px var(--mono);text-transform:uppercase;
  letter-spacing:.5px;padding:4px 9px;border-radius:999px;border:1px solid transparent}
.pill.critical{color:var(--crit);background:var(--crit-bg);border-color:#f3c2c8}
.pill.high{color:var(--high);background:var(--high-bg);border-color:#f2d3b4}
.pill.medium{color:var(--med);background:var(--med-bg);border-color:#e7dca2}
.pill.low{color:var(--low);background:var(--low-bg);border-color:#c7d6f7}
.pill.info{color:var(--info);background:var(--info-bg);border-color:#dbe1ea}
.status{display:inline-flex;align-items:center;gap:7px;font:12px var(--mono)}
.status.running{color:var(--accent2)} .status.done{color:var(--accent)} .status.error{color:var(--crit)}
.status .d{width:8px;height:8px;border-radius:50%;background:currentColor}
.status.running .d{animation:pulse 1.1s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:.35;transform:scale(.8)}50%{opacity:1;transform:scale(1.15)}}
.tools{display:flex;gap:5px;flex-wrap:wrap}
.tag{font:600 11px var(--mono);color:var(--muted);background:var(--bg2);border:1px solid var(--border2);
  padding:3px 8px;border-radius:6px;letter-spacing:.3px}
.tag.nmap{color:#2563eb} .tag.zap{color:#c2410c} .tag.sqlmap{color:#dc2626} .tag.tshark{color:#0f766e}
.rep-link{font:600 12px var(--sans);color:var(--accent);border:1px solid var(--accent-dim);
  padding:6px 12px;border-radius:8px;transition:background .15s;white-space:nowrap}
.rep-link:hover{background:rgba(15,118,110,.08);text-decoration:none}
.rep-link.disabled{opacity:.45;color:var(--faint);border-color:var(--border);
  pointer-events:none;cursor:not-allowed;background:transparent}
.empty{color:var(--faint);text-align:center;padding:34px}
.warn{color:var(--med);cursor:help;font-size:13px}
td.actions{white-space:nowrap}
.act-row{display:flex;gap:8px;align-items:center;justify-content:flex-end}
.act-row form{margin:0;display:inline-flex}
.del{font:600 13px var(--sans);color:var(--faint);background:transparent;cursor:pointer;
  border:1px solid var(--border2);border-radius:8px;padding:6px 10px;line-height:1;transition:.15s}
.del:hover{color:var(--crit);border-color:#f3c2c8;background:var(--crit-bg)}
.hist-head{display:flex;align-items:center;justify-content:space-between;margin:26px 0 12px;gap:12px}
.hist-head .section-h{margin:0}
.del-all{font:600 12px var(--sans);color:var(--muted);background:transparent;cursor:pointer;
  border:1px solid var(--border2);border-radius:8px;padding:8px 14px;transition:.15s}
.del-all:hover{color:var(--crit);border-color:#f3c2c8;background:var(--crit-bg)}

/* findings (report) */
.finding{display:flex;gap:0;background:var(--panel);border:1px solid var(--border);
  border-radius:12px;margin-bottom:10px;overflow:hidden;animation:rise .3s ease both}
.finding .accent{width:4px;background:var(--c);flex:none}
.finding .body{padding:14px 16px;flex:1;min-width:0}
.finding .top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.finding .ftype{font-weight:600;font-size:15px}
.finding .ftgt{font-family:var(--mono);font-size:12px;color:var(--muted);margin:7px 0;word-break:break-all}
.finding .fev{font-size:13px;color:var(--muted);line-height:1.5;margin-top:6px}
.finding .fev.code{font-family:var(--mono);font-size:12px;color:#1e40af;background:var(--bg2);
  border:1px solid var(--border);border-radius:8px;padding:9px 11px;white-space:pre-wrap;word-break:break-all}
@keyframes rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.section-h{font-size:12px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted);margin:26px 0 12px}
.back{font:13px var(--sans);color:var(--muted)}
.steps{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:6px 18px}
.steps li{margin:10px 0;font-size:14px}

@media (max-width:720px){.stats{grid-template-columns:repeat(2,1fr)}.wrap{padding:0 16px 48px}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""

MESH_MARK = ('<svg class="mark" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">'
  '<path d="M20 7 20 21 7 30M20 21 33 30M7 30 33 30" stroke="#94a3b8" stroke-width="1.4"/>'
  '<circle cx="20" cy="7" r="3.2" fill="#0f766e"/><circle cx="7" cy="30" r="3.2" fill="#2563eb"/>'
  '<circle cx="33" cy="30" r="3.2" fill="#0f766e"/><circle cx="20" cy="21" r="2.6" fill="#101b2d"/></svg>')


def _page(title: str, body: str, refresh: str = "") -> bytes:
    fonts = ("<link rel=preconnect href='https://fonts.googleapis.com'>"
             "<link rel=preconnect href='https://fonts.gstatic.com' crossorigin>"
             "<link rel=stylesheet href='https://fonts.googleapis.com/css2?"
             "family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&"
             "family=JetBrains+Mono:wght@400;500;600&display=swap'>")
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title>{refresh}{fonts}<style>{SITE_CSS}</style></head><body>"
            f"<header><div class=hdr>{MESH_MARK}"
            f"<div class=brand><b>ScanMesh</b><span>Security orchestrator</span></div>"
            f"<div class=spacer></div><div class=badge-auth>authorized targets only</div>"
            f"</div></header><div class=wrap>{body}</div></body></html>").encode()


def _sev_counts(findings) -> dict:
    return {s: sum(1 for f in findings if f.severity == s) for s in SEV_UI}


def _stat_tiles(counts: dict) -> str:
    return '<div class=stats>' + "".join(
        f'<div class="tile sev-{s}"><div class=num>{counts.get(s,0)}</div>'
        f'<div class=lab><span class=dot></span>{s}</div></div>' for s in SEV_UI) + '</div>'


def _dist_bar(counts: dict) -> str:
    total = sum(counts.values()) or 1
    segs = "".join(
        f'<span class="sev-{s}" style="width:{counts[s]/total*100:.1f}%;background:var(--c)"></span>'
        for s in SEV_UI if counts.get(s))
    return f'<div class=dist>{segs}</div>'


def _tool_tags(tools) -> str:
    return '<div class=tools>' + "".join(
        f'<span class="tag {html.escape(t)}">{html.escape(t)}</span>' for t in sorted(tools)) + '</div>'


def index_page() -> bytes:
    c = db()
    rows = c.execute("""SELECT id,target,kind,status,created FROM scans
        ORDER BY id DESC LIMIT 100""").fetchall()
    counts = {s: 0 for s in SEV_UI}
    for (sev,) in c.execute("SELECT severity FROM findings"):
        if sev in counts:
            counts[sev] += 1
    c.close()

    def status_cell(st):
        if st == "running":
            return '<span class="status running"><span class=d></span>running</span>'
        if st.startswith("error"):
            return (f'<span class="status error" title="{html.escape(st)}">'
                    f'<span class=d></span>error</span>')
        warn = (f' <span class=warn title="{html.escape(st)}">&#9888;</span>'
                if st != "done" else "")
        return f'<span class="status done"><span class=d></span>done</span>{warn}'

    kind_label = {"web": "full", "quick": "quick", "nmap": "ports"}
    rows_html = []
    for i, t, k, st, cr in rows:
        report = (f"<a class=rep-link href='/scan?id={i}'>Report &rarr;</a>"
                  if st != "running" else
                  "<span class='rep-link disabled' title='Report ready when the scan finishes'>Report &rarr;</span>")
        rows_html.append(
            f"<tr><td class=t-id>#{i}</td><td class=mono>{html.escape(t)}</td>"
            f"<td><span class=tag>{kind_label.get(k, html.escape(k))}</span></td>"
            f"<td>{status_cell(st)}</td><td class=mono style='color:var(--faint)'>{html.escape(cr[:19])}</td>"
            f"<td class=actions><div class=act-row>{report}"
            f"<form method=post action=/delete onsubmit=\"return confirm('Delete scan #{i}?')\">"
            f"<input type=hidden name=id value={i}>"
            f"<button class=del type=submit title='Delete scan'>&#10005;</button></form>"
            f"</div></td></tr>")
    tbody = "".join(rows_html) or "<tr><td colspan=6 class=empty>No scans yet — run one above.</td></tr>"
    # refresh statuses while a scan runs, but NOT while you're using the target
    # box - so an in-progress scan never interrupts you starting another one
    refresh = ("<script>setTimeout(function(){var t=document.getElementById('target');"
               "if(!(t&&(t.value||document.activeElement===t)))location.reload();},4000);</script>"
               ) if any(r[3] == "running" for r in rows) else ""
    clear_all = ("<form method=post action=/delete "
                 "onsubmit=\"return confirm('Delete ALL scan history?')\">"
                 "<input type=hidden name=all value=1>"
                 "<button class=del-all type=submit>Clear history</button></form>"
                 ) if rows else ""

    body = f"""<h1 class=page>Scan console</h1>
<p class=sub>Orchestrate nmap &middot; ZAP &middot; sqlmap &middot; tshark against one target &mdash; one correlated report.</p>
<div class=card>
<form class=scan-form method=post action=/scan>
  <div class=field>
    <label class=lbl for=target>Target</label>
    <input id=target type=text name=target required
      placeholder="http://host/path?id=1   or   192.168.1.10">
  </div>
  <div class=field style="flex:none">
    <label class=lbl>Scan type</label>
    <div class=seg>
      <input type=radio name=kind id=k-web value=web checked><label for=k-web>Full scan</label>
      <input type=radio name=kind id=k-quick value=quick><label for=k-quick>Quick scan</label>
      <input type=radio name=kind id=k-nmap value=nmap><label for=k-nmap>Ports</label>
    </div>
  </div>
  <button class=btn type=submit>Run scan</button>
  <div class=hint>Full = crawl whole site (slow). Quick = single URL (fast). Web scans need the ZAP daemon running. Authorized targets only.</div>
</form>
</div>
{_stat_tiles(counts)}
<div class=hist-head><div class=section-h>Scan history</div>{clear_all}</div>
<div class=card style="padding:6px 0">
<table class=tbl><thead><tr><th>ID</th><th>Target</th><th>Type</th><th>Status</th><th>Started</th><th></th></tr></thead>
<tbody>{tbody}</tbody></table>
</div>"""
    return _page("ScanMesh", body, refresh)


def report_page(sid: int, target: str, findings, steps) -> bytes:
    counts = _sev_counts(findings)
    rows = sorted(findings, key=lambda f: -sm.SEV_ORDER.index(f.severity))
    cards = []
    for f in rows:
        ev = html.escape(f.evidence or "")
        code = " code" if f.tool in ("tshark", "sqlmap") or "\n" in (f.evidence or "") else ""
        cards.append(
            f'<div class="finding sev-{f.severity}"><div class=accent></div><div class=body>'
            f'<div class=top><span class="pill {f.severity}">{f.severity}</span>'
            f'<span class=ftype>{html.escape(f.finding_type)}</span></div>'
            f'<div class=ftgt>{html.escape(f.target)}</div>'
            f'{_tool_tags(f.tools)}'
            + (f'<div class="fev{code}">{ev}</div>' if ev else '')
            + '</div></div>')
    findings_html = "".join(cards) or "<div class=empty>No findings.</div>"
    steps_html = "".join(f"<li>{html.escape(s)}</li>" for s in steps) or "<li style='color:var(--faint)'>None — no follow-up actions.</li>"
    total = sum(counts.values())
    body = f"""<p class=back><a href="/">&larr; Console</a></p>
<h1 class=page>Report</h1>
<p class=sub><span class=mono>{html.escape(target)}</span> &middot; {total} findings</p>
{_stat_tiles(counts)}
{_dist_bar(counts)}
<div class=section-h>Findings</div>
{findings_html}
<div class=section-h>Suggested next steps <span style="color:var(--faint)">(operator-run)</span></div>
<ul class=steps>{steps_html}</ul>"""
    return _page(f"Report - {target}", body)


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
            label = f"{row[0]}" if row else f"scan #{sid}"
            findings = _load_findings(sid)
            steps = sm.next_steps(findings)
            self._send(report_page(sid, label, findings, steps))
        else:
            self._send(b"not found", 404)

    def _redirect_home(self):
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        n = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(n).decode())

        if path == "/delete":
            c = db()
            if form.get("all"):
                c.execute("DELETE FROM findings")
                c.execute("DELETE FROM scans")
            elif form.get("id", [""])[0].isdigit():
                sid = int(form["id"][0])
                c.execute("DELETE FROM findings WHERE scan_id=?", (sid,))
                c.execute("DELETE FROM scans WHERE id=?", (sid,))
            c.commit()
            c.close()
            return self._redirect_home()

        if path != "/scan":
            return self._send(b"not found", 404)
        target = form.get("target", [""])[0].strip()
        kind = form.get("kind", ["nmap"])[0]
        if kind not in ("web", "quick", "nmap"):
            kind = "nmap"
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
        self._redirect_home()


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
