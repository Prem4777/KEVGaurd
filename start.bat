@echo off
setlocal

set ROOT=%~dp0
cd /d "%ROOT%"

echo ============================================
echo  KEVGuard - Starting all services
echo ============================================
echo.

REM ── 1. Coral bridge ──────────────────────────────────────────────────────────
echo [1/3] Starting Coral bridge on http://127.0.0.1:8787 ...
start "Coral Bridge" cmd /k "cd /d "%ROOT%" && node scripts/coral-bridge.mjs"

REM Give the bridge a moment to start
timeout /t 3 /nobreak >nul

REM ── 2. FastAPI backend ───────────────────────────────────────────────────────
echo [2/3] Starting FastAPI backend on http://127.0.0.1:8000 ...
start "FastAPI Backend" cmd /k "cd /d "%ROOT%backend" && uvicorn app.main:app --reload --port 8000"

REM Give the backend a moment to start
timeout /t 3 /nobreak >nul

REM ── 3. React frontend ────────────────────────────────────────────────────────
echo [3/3] Starting React frontend on http://localhost:5173 ...
start "React Frontend" cmd /k "cd /d "%ROOT%frontend" && npm run dev"

echo.
echo ============================================
echo  All services launched in separate windows.
echo  Coral Bridge : http://127.0.0.1:8787
echo  API          : http://127.0.0.1:8000
echo  App          : http://localhost:5173
echo ============================================
echo.
echo  Close this window or press any key to exit.
pause >nul
