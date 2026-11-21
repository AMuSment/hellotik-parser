@echo off
setlocal
rem ============================================================
rem  hellotik WebUI : LAN only (no public tunnel)
rem  usage:  start-lan.cmd [port]      default 8765
rem  token:  generated on first run, saved in webui_token.txt
rem  NOTE:   LAN access from other devices needs a firewall rule
rem          once, as Administrator:
rem          New-NetFirewallRule -DisplayName hellotik-WebUI ^
rem            -Direction Inbound -Protocol TCP -LocalPort 8765 -Action Allow
rem ============================================================
set HERE=%~dp0
set PORT=%~1
if "%PORT%"=="" set PORT=8765

rem python：优先 DSH 内置运行时（本机 python.exe 常是应用商店占位符，跑不了这段代码）
set PY=
for %%R in (dsh-next-primary-runtime dsh-primary-runtime) do (
  if not defined PY if exist "%USERPROFILE%\.dsh\dsh-runtimes\%%R\dependencies\python\python.exe" (
    set "PY=%USERPROFILE%\.dsh\dsh-runtimes\%%R\dependencies\python\python.exe"
  )
)
if not defined PY (
  where py.exe >nul 2>nul && set "PY=py -3"
)
if not defined PY (
  where python.exe >nul 2>nul && set "PY=python.exe"
)
if not defined PY (
  echo [x] python 3 not found - install it or set PY in this file.
  exit /b 1
)

if exist "%HERE%webui_token.txt" goto havetoken
"%PY%" -c "import secrets,sys;open(sys.argv[1],'w',encoding='utf-8').write(secrets.token_urlsafe(9))" "%HERE%webui_token.txt"
:havetoken
set /p TOK=<"%HERE%webui_token.txt"

echo.
echo   hellotik WebUI (LAN only)
echo   token    : %TOK%
echo   local    : http://127.0.0.1:%PORT%/?k=%TOK%
echo   LAN      : http://192.168.1.10:%PORT%/?k=%TOK%
echo.
echo   If another device cannot open the LAN address, run this once
echo   in an Administrator PowerShell:
echo     New-NetFirewallRule -DisplayName hellotik-WebUI -Direction Inbound -Protocol TCP -LocalPort %PORT% -Action Allow
echo.
echo   Stop: close this window or press Ctrl+C.
echo.
"%PY%" "%HERE%hellotik_webui.py" --public --port %PORT% --token %TOK%
endlocal