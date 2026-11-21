# -*- coding: utf-8 -*-
"""把 hellotik_webui.py 挂到局域网并脱离当前会话常驻。

    python tools/serve_detached.py            # 起在 8765（已在跑就只报现状）
    python tools/serve_detached.py 8080       # 换端口
    python tools/serve_detached.py --status   # 只看状态
    python tools/serve_detached.py --stop     # 停

为什么要绕一层 WMI：agent / 终端 / 一次性的 bash 进程都活在 Windows Job Object 里，
直接 Popen 出来的子进程会跟着作业结束被杀（DETACHED_PROCESS 也救不了，作业不允许 breakaway）。
Win32_Process.Create 的父级是 WmiPrvSE，不在这个作业里，才能真正常驻。

口令复用 webui_token.txt（没有就生成）；日志 webui.log / webui.err.log；PID 写 webui.pid。
"""
import io
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
TOKEN_FILE = os.path.join(ROOT, "webui_token.txt")
PID_FILE = os.path.join(ROOT, "webui.pid")
WRAP = os.path.join(ROOT, "_serve.cmd")
LOG = os.path.join(ROOT, "webui.log")
ERR = os.path.join(ROOT, "webui.err.log")

PORT = 8765
STOP = "--stop" in sys.argv
STATUS = "--status" in sys.argv
for arg in sys.argv[1:]:
    if arg.isdigit():
        PORT = int(arg)


def token(create=True):
    if os.path.exists(TOKEN_FILE):
        t = io.open(TOKEN_FILE, encoding="utf-8").read().strip()
        if t:
            return t
    if not create:
        return ""
    t = secrets.token_urlsafe(9)
    io.open(TOKEN_FILE, "w", encoding="utf-8").write(t)
    return t


def probe(tok=None):
    tok = tok if tok is not None else token(create=False)
    url = "http://127.0.0.1:%d/api/status" % PORT + (("?k=" + tok) if tok else "")
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def port_pid(port=None):
    """谁在监听这个端口（netstat 的最后一列）"""
    port = port or PORT
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    except Exception:
        return None
    pat = re.compile(r"[:.]%d\s+\S+\s+LISTENING\s+(\d+)" % port)
    for line in out.splitlines():
        m = pat.search(line)
        if m:
            return int(m.group(1))
    return None


def pid_alive(pid):
    if not pid:
        return False
    try:
        out = subprocess.run(["tasklist", "/FI", "PID eq %d" % pid],
                             capture_output=True, text=True).stdout
        return str(pid) in out
    except Exception:
        return False


def lan_ips():
    ips = []
    try:
        out = subprocess.run(["ipconfig"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            if "IPv4" in line and ":" in line:
                ip = line.rsplit(":", 1)[1].strip()
                if ip.count(".") == 3 and not ip.startswith("127."):
                    ips.append(ip)
    except Exception:
        pass
    return ips


def report(tok, st, pid=None):
    pid = pid or port_pid()
    print("  口令   %s" % tok)
    print("  本机   http://127.0.0.1:%d/?k=%s" % (PORT, tok))
    for ip in lan_ips():
        print("  局域网 http://%s:%d/?k=%s" % (ip, PORT, tok))
    if pid:
        print("  PID    %d（日志 webui.log / webui.err.log）" % pid)
    if st:
        print("  状态   " + json.dumps(st, ensure_ascii=False))
    print("  停止   python tools/serve_detached.py --stop")


def stop():
    pid = port_pid() or (int(io.open(PID_FILE).read().strip())
                         if os.path.exists(PID_FILE) else None)
    if not pid_alive(pid):
        print("没在跑（端口 %d 无监听）" % PORT)
        for f in (PID_FILE, WRAP):
            if os.path.exists(f):
                os.remove(f)
        return 0
    subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
    for _ in range(25):
        time.sleep(0.2)
        if not pid_alive(pid):
            print("已停止 pid=%d" % pid)
            for f in (PID_FILE, WRAP):
                if os.path.exists(f):
                    try:
                        os.remove(f)
                    except OSError:
                        pass
            return 0
    print("停止失败，pid=%d 仍在" % pid)
    return 1


def write_wrapper(tok):
    """WMI 只负责执行一个 .cmd：把引号都放在文件里，绕开命令行嵌套引号的坑"""
    lines = [
        "@echo off",
        'cd /d "%s"' % ROOT,
        '"%s" -u hellotik_webui.py --public --port %d --token %s >> "%s" 2>> "%s"'
        % (PY, PORT, tok, LOG, ERR),
    ]
    io.open(WRAP, "w", encoding="utf-8", newline="\r\n").write("\r\n".join(lines) + "\r\n")
    return WRAP


def wmi_run(script):
    ps = ("$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
          "-Arguments @{CommandLine='%s'}; "
          "$r | Select-Object ReturnValue,ProcessId | ConvertTo-Json -Compress"
          % script.replace("'", "''"))
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, text=True)
    try:
        return json.loads(r.stdout)
    except Exception:
        print("WMI 启动失败：%s%s" % (r.stdout, r.stderr))
        return {"ReturnValue": -1, "ProcessId": 0}


def main():
    tok = token()
    st = probe(tok)
    if STATUS:
        if st:
            print("运行中")
            report(tok, st)
            return 0
        print("没在跑（端口 %d 无响应）" % PORT)
        return 1
    if STOP:
        return stop()
    if st:
        print("已在运行")
        report(tok, st)
        return 0

    wrap = write_wrapper(tok)
    res = wmi_run('cmd /c "%s"' % wrap)
    if res.get("ReturnValue") not in (0, None):
        print("WMI 返回 %s" % res)
        return 2

    for _ in range(60):
        time.sleep(0.25)
        st = probe(tok)
        if st:
            pid = port_pid()
            if pid:
                io.open(PID_FILE, "w").write(str(pid))
            print("已启动")
            report(tok, st, pid)
            return 0
    print("启动超时，看 webui.err.log")
    try:
        print(io.open(ERR, encoding="utf-8", errors="replace").read()[-800:])
    except OSError:
        pass
    return 3


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    sys.exit(main())
