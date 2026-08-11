@echo off
REM One-command ScanMesh demo launcher (Windows).
REM Starts ZAP + the vulnerable demo target + the web UI, then opens the browser.
setlocal

echo ==============================================
echo   ScanMesh demo - starting services...
echo ==============================================

REM attach live packet-capture evidence on the loopback adapter
set SCANMESH_CAPTURE_IFACE=\Device\NPF_Loopback

start "ScanMesh - ZAP"    cmd /k zap-daemon
start "ScanMesh - Target" cmd /k python "%~dp0demo_target.py"

echo Waiting ~30s for ZAP to warm up...
timeout /t 30 /nobreak >nul

start "ScanMesh - Web UI" cmd /k "set SCANMESH_CAPTURE_IFACE=%SCANMESH_CAPTURE_IFACE% && python "%~dp0web.py""
timeout /t 3 /nobreak >nul
start "" http://127.0.0.1:8000

echo.
echo   UI:            http://127.0.0.1:8000
echo   Demo target:   http://127.0.0.1:8099/products?cat=1
echo.
echo   In the UI, pick "Web scan" and use the demo target URL above.
echo   Close the opened windows to stop everything.
echo.
pause
