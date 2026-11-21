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