@echo off
setlocal
rem ============================================================
rem  hellotik WebUI : local service + LAN listen + public tunnel
rem  usage:  start-public.cmd [port]      default 8765
rem  token:  generated on first run, saved in webui_token.txt
rem ============================================================
set HERE=%~dp0
set PORT=%~1
if "%PORT%"=="" set PORT=8765

set PY=C:\Users\28672\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe
if not exist "%PY%" set PY=python.exe
set CFD=%HERE%bin\cloudflared.exe

if exist "%HERE%webui_token.txt" goto havetoken
"%PY%" -c "import secrets,sys;open(sys.argv[1],'w',encoding='utf-8').write(secrets.token_urlsafe(9))" "%HERE%webui_token.txt"
:havetoken
set /p TOK=<"%HERE%webui_token.txt"

echo.
echo   hellotik WebUI starting...
echo   token    : %TOK%
echo   local    : http://127.0.0.1:%PORT%/?k=%TOK%
echo   LAN      : http://192.168.1.10:%PORT%/?k=%TOK%
echo              (LAN from other devices may need a firewall rule - see REA_report.md section 10)
echo   public   : see the cloudflared window for the https://xxx.trycloudflare.com link
echo.

start "hellotik-webui" "%PY%" "%HERE%hellotik_webui.py" --public --port %PORT% --token %TOK%
timeout /t 2 /nobreak >nul
if not exist "%CFD%" goto nocfd
start "cloudflared" "%CFD%" tunnel --no-autoupdate --url http://127.0.0.1:%PORT%
goto done

:nocfd
echo   [!] bin\cloudflared.exe not found - only local + LAN service started.

:done
echo.
echo   close those two windows to stop.
endlocal