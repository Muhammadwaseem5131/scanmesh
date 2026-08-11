# ScanMesh — local tool setup (this machine)

Tools live in `D:\SecTools` (outside the repo). PATH and env vars below are
already set for user **GEF** — open a **new** terminal for them to take effect.

## Installed & verified

| Tool | Location | Command | Status |
|---|---|---|---|
| nmap | (system) | `nmap` | ✅ working |
| sqlmap | `D:\SecTools\sqlmap` | `sqlmap` (shim → `python sqlmap.py`) | ✅ working |
| OWASP ZAP 2.17 | `D:\SecTools\ZAP_2.17.0` | `zap-daemon` (starts daemon) | ✅ working |
| Wireshark/tshark | `C:\Program Files\Wireshark` | `tshark` | ✅ working (4.6.7 + Npcap) |

Environment already configured:
- PATH += `D:\SecTools\bin`, `C:\Program Files\Wireshark`
- `SCANMESH_SQLMAP = python D:\SecTools\sqlmap\sqlmap.py` (so the connector finds sqlmap)

## Running a scan

```bat
:: 1) start ZAP once, in its own terminal (leave it running)
zap-daemon

:: 2) in another terminal, run scans
python scanmesh.py 127.0.0.1          :: nmap -> report.html
sqlmap -u "http://target/x?id=1" --batch   :: sqlmap directly, if needed
```

ZAP API: `http://127.0.0.1:8090`, key `scanmesh123` (change in
`D:\SecTools\bin\zap-daemon.cmd`).

## Wireshark — installed

Wireshark 4.6.7 + Npcap are installed and verified: a real loopback capture
through the tshark connector captured 104 packets and parsed the HTTP request
as evidence. `tshark` is on PATH. (Some interfaces may need an Administrator
terminal to capture; loopback worked without one here.)

## Verified end-to-end (2026-08-11)

Against a local deliberately-injectable test app, the installed tools produced
one correlated report:

- sqlmap → `critical` SQL Injection
- ZAP → `high` SQL Injection + 4 config/header issues

`python scanmesh.py --demo` self-check passes offline with no tools installed.
