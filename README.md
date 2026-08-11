# ScanMesh

A rule-based security-tool orchestrator. It chains free, industry-standard
scanners — **nmap → OWASP ZAP → sqlmap → tshark** — into one pipeline that
discovers hosts, scans web apps, confirms injection, captures evidence, then
correlates every tool's output into a single de-duplicated report.

**100% deterministic. No AI/LLM anywhere in the pipeline.** Every decision is a
plain `if`/lookup rule.

## Authorized use only

This tool is for authorized security testing only — infrastructure you own,
owned lab environments, or engagements with explicit written permission. It
does not scan or exploit on its own; it orchestrates and correlates output from
user-operated tools that you have already configured and are authorized to run.
It **suggests** next steps (e.g. "run sqlmap here") — the operator pulls the
trigger.

## Quick start

```bash
python scanmesh.py --demo        # offline self-check, needs no external tools
python scanmesh.py 127.0.0.1     # live nmap scan -> report.html
```

`--demo` runs a full offline self-check of every parser and rule, so a fresh
clone verifies with zero external tools installed.

## Tools

| Stage | Tool | Cost | Install |
|---|---|---|---|
| Host/port discovery | nmap | free | https://nmap.org |
| Web app scanner | OWASP ZAP | free | `zap.sh -daemon -config api.key=<key>` |
| SQLi confirmation | sqlmap | free | `pip install sqlmap` |
| Evidence capture | tshark | free | install Wireshark, add to PATH |
| Acunetix / Burp | *optional* | paid | connectors included but marked `UNTESTED` |

ZAP is the free drop-in for the web-scanner role — it replaces the paid
Acunetix/Burp scanners (Burp's scanner + REST API are Pro/Enterprise only on
every OS; Acunetix has no free tier). The Acunetix/Burp connectors are left in
place, clearly marked, for licensed engagements.

Only `requests` is needed, and only for the REST connectors (ZAP/Acunetix/Burp)
at run time — it is imported lazily, so the module and `--demo` work without it.

```bash
pip install -r requirements.txt
```

## Lab targets

Never point this at anything you don't own or have written authorization for.
Safe practice targets: DVWA, OWASP Juice Shop, Metasploitable2 — run them inside
an isolated VM/VLAN with no internet exposure.

## How it works

Every connector normalizes to one `Finding` schema. `correlate()` merges
findings that share `(target, finding_type)`, keeps the highest severity, and
unions the contributing tools (more tools agreeing = higher confidence). The
rule engine advises the next tool to run based on prior results
(web port open → ZAP; ZAP finds SQLi → sqlmap). One HTML report comes out.
