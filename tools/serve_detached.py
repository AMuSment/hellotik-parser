# -*- coding: utf-8 -*-
"""把 hellotik_webui.py 以「完全脱离终端」的方式挂到局域网（关掉窗口也不会停）。

    python tools/serve_detached.py            # 默认端口 8765
    python tools/serve_detached.py 8080       # 自定义端口

- 用 DETACHED_PROCESS 启动：本脚本（或双击它的 cmd 窗口）退出后服务照常运行
- 口令取 webui_token.txt（没有就生成一个），日志写 webui.log / webui.err.log，PID 写 webui.pid
- 已经在跑就直接报现状，不重复起；停止用 `python tools/serve_detached.py --stop`
"""
import io
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
TOKEN_FILE = os.path.join(ROOT, "webui_token.txt")
PID_FILE = os.path.join(ROOT, "webui.pid")

PORT = 8765
for arg in sys.argv[1:]:
    if arg.isdigit():
        PORT = int(arg)
STOP = "--stop" in sys.argv


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


def probe(tok):
    url = "http://127.0.0.1:%d/api/status?k=%s" % (PORT, tok)
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def pid_alive(pid):
    try:
        out = subprocess.run(["tasklist", "/FI", "PID eq %d" % pid],
                             capture_output=True, text=True).stdout
        return str(pid) in out
    except Exception:
        return False


def read_pid():
    try:
        return int(io.open(PID_FILE).read().strip())
    except Exception:
        return None


def stop():
    pid = read_pid()
    if not pid or not pid_alive(pid):
        print("没有在跑（%s 里没有有效 PID）" % PID_FILE)
        return 0
    subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
    for _ in range(20):
        time.sleep(0.2)
        if not pid_alive(pid):
            print("已停止 pid=%d" % pid)
            try:
                os.remove(PID_FILE)
            except OSError:
                pass
            return 0
    print("停止失败，pid=%d 仍在" % pid)
    return 1


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


def main():
    if STOP:
        return stop()
    tok = token()
    st = probe(tok)
    if st:
        print("已在运行 pid=%s" % (read_pid() or "?"))
        report(tok, st)
        return 0

    out = open(os.path.join(ROOT, "webui.log"), "ab")
    err = open(os.path.join(ROOT, "webui.err.log"), "ab")
    flags = 0x00000008 | 0x00000200          # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    p = subprocess.Popen(
        [PY, "-u", os.path.join(ROOT, "hellotik_webui.py"),
         "--public", "--port", str(PORT), "--token", tok],
        cwd=ROOT, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
        creationflags=flags, close_fds=True)
    out.close()
    err.close()
    io.open(PID_FILE, "w").write(str(p.pid))

    for _ in range(40):
        time.sleep(0.25)
        st = probe(tok)
        if st:
            print("已启动 pid=%d" % p.pid)
            report(tok, st)
            return 0
    print("启动失败 pid=%d，看 webui.err.log" % p.pid)
    return 1


def report(tok, st):
    print("  口令   %s" % tok)
    print("  本机   http://127.0.0.1:%d/?k=%s" % (PORT, tok))
    for ip in lan_ips():
        print("  局域网 http://%s:%d/?k=%s" % (ip, PORT, tok))
    print("  状态   " + json.dumps(st, ensure_ascii=False))
    print("  停止   python tools/serve_detached.py --stop")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    sys.exit(main())
