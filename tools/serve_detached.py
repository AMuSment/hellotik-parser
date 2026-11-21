# -*- coding: utf-8 -*-
"""把 hellotik_webui.py 挂到局域网并脱离当前会话常驻。

    python tools/serve_detached.py            # 起在 8765（已在跑就只报现状）
    python tools/serve_detached.py 8080       # 换端口
    python tools/serve_detached.py --status   # 只看状态
    python tools/serve_detached.py --stop     # 停

为什么要绕 WMI：从终端 / IDE / agent 里 Popen 出来的子进程都挂在同一个 Job Object 上，
窗口一关整棵树被回收（DETACHED_PROCESS 也不行，作业不允许 breakaway）。
Win32_Process.Create 的父级是 WmiPrvSE，不在这个作业里。

并且必须带 CREATE_NO_WINDOW|CREATE_NEW_PROCESS_GROUP：WMI 默认让子进程共用调用方的控制台，
终端一关子进程照样吃 CTRL_CLOSE，日志里会留下一行 ^C 然后服务消失。
窗口/句柄全断掉之后，日志由 hellotik_webui.py 的 --daemon 自己写文件。

口令复用 webui_token.txt（没有就生成）；日志 webui.log；PID 写 webui.pid。
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
LOG = os.path.join(ROOT, "webui.log")

# CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP：不共用调用方控制台，Ctrl+C 也不进这个组
CREATE_FLAGS = 0x08000000 | 0x00000200

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
        print("  PID    %d（日志 webui.log）" % pid)
    if st:
        print("  状态   " + json.dumps(st, ensure_ascii=False))
    print("  停止   python tools/serve_detached.py --stop")


def stop():
    pid = port_pid() or (int(io.open(PID_FILE).read().strip())
                         if os.path.exists(PID_FILE) else None)
    if not pid_alive(pid):
        print("没在跑（端口 %d 无监听）" % PORT)
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        return 0
    subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
    for _ in range(25):
        time.sleep(0.2)
        if not pid_alive(pid):
            print("已停止 pid=%d" % pid)
            if os.path.exists(PID_FILE):
                try:
                    os.remove(PID_FILE)
                except OSError:
                    pass
            return 0
    print("停止失败，pid=%d 仍在" % pid)
    return 1


def wmi_run(script):
    """用 Win32_Process.Create 拉起；PowerShell 里单引号转义即可，不再经过 cmd 剥引号"""
    ps = (
        "$si = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly "
        "-Property @{CreateFlags=[uint32]%d}; "
        "$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
        "-Arguments @{CommandLine='%s'; CurrentDirectory='%s'; ProcessStartupInformation=$si}; "
        "$r | Select-Object ReturnValue,ProcessId | ConvertTo-Json -Compress"
        % (CREATE_FLAGS, script.replace("'", "''"), ROOT.replace("'", "''"))
    )
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

    cmdline = '"%s" -u hellotik_webui.py --public --port %d --token %s --daemon --log "%s"' % (
        PY, PORT, tok, LOG)
    res = wmi_run(cmdline)
    if res.get("ReturnValue") not in (0, None):
        print("WMI 返回 %s" % res)
        return 2

    for _ in range(80):
        time.sleep(0.25)
        st = probe(tok)
        if st:
            pid = port_pid()
            if pid:
                io.open(PID_FILE, "w").write(str(pid))
            print("已启动")
            report(tok, st, pid)
            return 0
    print("启动超时，看 webui.log 末尾")
    try:
        print(io.open(LOG, encoding="utf-8", errors="replace").read()[-800:])
    except OSError:
        pass
    return 3


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    sys.exit(main())
