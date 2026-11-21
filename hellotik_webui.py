#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hellotik 解析 · 本地/局域网 WebUI

复用 hellotik_dl.py 里已验证的协议实现，对外提供：
  GET  /                     前端页面
  POST /api/parse            {url}      -> 票据+解析，秒回基础档位（阶段一）
  POST /api/more             {sid}      -> 追取更高码率 + 逐档体积/分辨率（阶段二）
  POST /api/resolve          {url}      -> 一次性跑完两阶段（脚本用）
  GET  /api/file?u=&name=     服务端经 hellotik 换链后流式下载
  GET  /api/img?u=            封面代取（源站有 Referer 防盗链）
  GET  /api/status
  POST /api/compress         {src,name,height,orig,vid} -> ffmpeg 重编码出小体积 mp4
  GET  /api/cfile?key=&name=  下发压缩产物（cache/）

平台：
  抖音 / 小红书 / 快手 —— 走 hellotik.app 的票据+解析协议（见 hellotik_dl.py、REA_report.md）
  X（推特）—— 站方不支持；元数据走 x2twitter/savetwitter 的 ajaxSearch，文件走其
  dl.snapcdn.app 服务端代理回源，因此本机无需能连上 x.com/video.twimg.com。

启动:
  # 只给本机
  python hellotik_webui.py --port 8765

  # 挂到局域网（自动生成访问口令，手机/别的电脑可用）
  python hellotik_webui.py --public
  python hellotik_webui.py --public --port 8080 --token 我的口令

  # 端口/网卡自定义
  python hellotik_webui.py --host 0.0.0.0 --port 8765 --token abc123
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import html as htmlmod
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import hellotik_dl as H  # noqa: E402

INDEX = os.path.join(HERE, "webui", "index.html")

# 允许被 /api/file 与 /api/img 代取的源站域名后缀（防止本服务变成任意 URL 代理）
ALLOW_SUFFIX = (
    ".douyinvod.com", ".douyin.com", ".douyinpic.com", ".iesdouyin.com", ".byteimg.com",
    ".xhscdn.com", ".xiaohongshu.com", ".xhslink.com",
    ".kuaishou.com", ".kwimgs.com", ".kwaicdn.com", ".yximgs.com",
    ".snapcdn.app",                     # x2twitter / savetwitter 的下载代理（X 视频/图片）
    ".twimg.com",                       # X 直链（yt-dlp 兜底时由本机直接出网，需在墙外/有代理）
)
PLATFORMS = H.PLATFORMS        # 平台表只有 hellotik_dl.py 一份

# ---- X（推特）：站方不提供 X，走 x2twitter/savetwitter（同一 snapcdn 后端，互为备份）
X_BASES = ("https://x2twitter.com", "https://savetwitter.net")
X_RX = r"(?:x\.com|twitter\.com)/[^/]+/status(?:es)?/(\d+)"
DIRECT_SUFFIX = (".snapcdn.app", ".twimg.com")   # 本身即下载代理/直链，不必再过 hellotik 换链

SESS_TTL = 900                       # 阶段一会话保留 15 分钟
SESSIONS = {}
_UWX = None
_LOCK = threading.Lock()
FIXTURE_MODE = False                 # --fixture 演示模式开关
FIXTURE_FAIL = False                 # --fixture-fail 演示限流报错路径
ACCESS_TOKEN = None                  # 访问口令；None = 不校验（仅本机模式）
COOKIE_NAME = "ht_k"
RATE_LIMIT = 120                     # 口令模式下每 IP 每分钟最多请求数
_RATE = {}                           # ip -> [window_start, count]

COMP_DONE_TTL = 6 * 3600             # 压缩记录保留 6 小时（够用户当天取回）
CACHE_MAX_BYTES = 2 * 1024 ** 3      # cache/ 上限 2 GiB，超了按 mtime 从旧到新回收
_LAST_GC = 0.0


def gc(force=False):
    """周期性清理：过期会话 / 压缩记录 / 换链缓存 / 限流桶 / 残留 .part / 缓存目录超限。
    原实现只在「新建会话」时清一次，没人点解析时这些表就永远不收缩。"""
    global _LAST_GC
    now = time.time()
    if not force and now - _LAST_GC < 60:
        return
    _LAST_GC = now
    with _LOCK:
        for k in [k for k, v in SESSIONS.items() if now - v.get("ts", 0) > SESS_TTL]:
            SESSIONS.pop(k, None)
        for k in [k for k, v in _COMP_DONE.items() if now - v.get("ts", 0) > COMP_DONE_TTL]:
            _COMP_DONE.pop(k, None)
        for k in [k for k, v in _PROXY.items() if now - v[1] > PROXY_TTL * 4]:
            _PROXY.pop(k, None)
        for ip in [ip for ip, (w, _) in _RATE.items() if now - w > 300]:
            _RATE.pop(ip, None)
    if not os.path.isdir(CACHE_DIR):
        return
    files, total = [], 0
    for fn in os.listdir(CACHE_DIR):
        fp = os.path.join(CACHE_DIR, fn)
        if not os.path.isfile(fp):
            continue
        try:
            st = os.stat(fp)
        except OSError:
            continue
        if fn.endswith(".part.mp4"):
            if now - st.st_mtime > 3600:          # 只清早已中断的临时文件
                _rm(fp)
            continue
        if fn.endswith(".mp4"):
            files.append((st.st_mtime, st.st_size, fp))
            total += st.st_size
    for _, sz, fp in sorted(files):
        if total <= CACHE_MAX_BYTES:
            break
        _rm(fp)
        total -= sz


def lan_ips():
    """列出本机可被局域网访问的 IPv4 地址。"""
    out = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip.startswith(("127.", "169.254.")) or ip in out:
                continue
            out.append(ip)
    except OSError:
        pass
    if not out:                       # 兜底：UDP 连一下外网看本地出口地址
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("223.5.5.5", 53))
            ip = s.getsockname()[0]
            if not ip.startswith(("127.", "169.254.")):
                out.append(ip)
        except OSError:
            pass
        finally:
            s.close()
    return out

# --fixture 演示模式：不碰站方接口，用一条真实抓取结果回放，用来验证前端渲染
FIXTURE = {
    "title": "让你在几秒钟之内记住我（示例数据）",
    "platform": "douyin",
    "type": "video",
    "qualityTier": "hd",
    "phase1": [("720p", 1454940, None), ("540p", 844227, None)],
    "phase2": [("原始档", 12890778, "1080x1916"), ("720p", 1454940, "720x1278"),
               ("1109kbps", 1074855, "1080x1916"), ("540p", 844227, "576x1022")],
}
_PNG_1PX = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==")

# ---------------------------------------------------------------- 压缩（重编码）
CACHE_DIR = os.path.join(HERE, "cache")
FFMPEG = None                       # ffmpeg 路径；None = 不支持压缩
# 目标高度 -> (CRF, 音频码率)
COMPRESS_PRESETS = {
    "1080": (24, "128k"),
    "720": (27, "96k"),
    "480": (29, "64k"),
    "360": (31, "48k"),
}
_COMP_SEM = threading.Semaphore(2)   # 同时最多两个编码任务
_COMP_DONE = {}                      # key -> {"size":int,"height":str,"name":str}


def find_ffmpeg():
    """找 ffmpeg：PATH → bin/ffmpeg.exe → bin/ffmpeg*/bin/ffmpeg.exe"""
    p = shutil.which("ffmpeg")
    if p:
        return p
    cands = [os.path.join(HERE, "bin", "ffmpeg.exe")]
    bindir = os.path.join(HERE, "bin")
    if os.path.isdir(bindir):
        for d in os.listdir(bindir):
            full = os.path.join(bindir, d)
            if os.path.isdir(full):
                cands.append(os.path.join(full, "bin", "ffmpeg.exe"))
                cands.append(os.path.join(full, "ffmpeg.exe"))
    for c in cands:
        if os.path.isfile(c):
            return c
    return None


def compress_video(src, name, height, orig_size=0, vid=""):
    """把源直链重编码成更小的 mp4，返回 {ok, key, size, ...}。

    缓存键用稳定身份（vid，通常是「分享链接|体积|标题」）+ 目标高度：抖音 CDN 直链每次
    解析都换签名，拿 src 当键会 100% miss。orig_size 参与键，避免同名视频相撞。
    """
    if FFMPEG is None:
        return {"ok": False, "error": "服务端没装 ffmpeg，压缩不可用；可改用「最小档」下载",
                "code": "NO_FFMPEG"}
    height = str(height)
    if height not in COMPRESS_PRESETS:
        return {"ok": False, "error": "不支持的目标画质：%s（可选 %s）"
                                      % (height, "/".join(COMPRESS_PRESETS))}
    ident = (vid or "").strip() or src
    key = hashlib.sha1(("%s|%s|%s" % (ident, height, int(orig_size or 0)))
                       .encode("utf-8")).hexdigest()[:16]
    out = os.path.join(CACHE_DIR, "%s.mp4" % key)
    pname = re.sub(r"[\\/:*?\"<>|\r\n]+", "_", name or "video").strip() or "video"
    stem = pname.rsplit(".", 1)[0]
    cname = "%s_压缩%s.mp4" % (stem, height)
    if os.path.isfile(out) and os.path.getsize(out) > 0:      # 命中缓存
        return {"ok": True, "key": key, "size": os.path.getsize(out), "height": height,
                "name": cname, "cached": True, "secs": 0}
    if not allowed(src):
        return {"ok": False, "error": "非白名单源站，拒绝处理"}
    _, page_path = detect(src)
    target = src if direct_src(src) else proxy_of(src, H.BASE + page_path)
    if not target:
        return {"ok": False, "error": "换链失败，拿不到可下载地址"}
    crf, abr = COMPRESS_PRESETS[height]
    os.makedirs(CACHE_DIR, exist_ok=True)
    tmp = out + ".part.mp4"
    cmd = [FFMPEG, "-y", "-nostdin", "-hide_banner", "-loglevel", "error",
           "-user_agent", H.UA, "-i", target,
           # 只取第一条视频轨和（可能存在的）音轨：源站有些档位是多轨/带字幕，直接编码会报错
           "-map", "0:v:0", "-map", "0:a:0?", "-sn", "-dn",
           "-vf", "scale=-2:%s" % height,
           "-c:v", "libx264", "-preset", "veryfast", "-crf", str(crf),
           "-profile:v", "high", "-pix_fmt", "yuv420p",
           "-c:a", "aac", "-b:a", abr, "-ac", "2",
           "-movflags", "+faststart", "-max_muxing_queue_size", "1024",
           "-f", "mp4", tmp]
    t0 = time.time()
    with _COMP_SEM:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=900)
        except subprocess.TimeoutExpired:
            _rm(tmp)
            return {"ok": False, "error": "编码超时（>15 分钟）"}
        except Exception as e:
            _rm(tmp)
            return {"ok": False, "error": "调用 ffmpeg 失败：%s" % e}
    if r.returncode != 0 or not os.path.isfile(tmp) or os.path.getsize(tmp) == 0:
        _rm(tmp)
        tail = (r.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        return {"ok": False, "error": "ffmpeg 编码失败：%s" % (tail[-1] if tail else "未知错误")}
    if not _is_mp4(tmp):                      # ffmpeg 偶发写出 0 字节/半截文件，别把坏文件放进缓存
        _rm(tmp)
        return {"ok": False, "error": "编码产物不是有效的 mp4（大小 %d 字节）"
                                      % (os.path.getsize(tmp) if os.path.exists(tmp) else 0)}
    os.replace(tmp, out)
    size = os.path.getsize(out)
    _COMP_DONE[key] = {"size": size, "height": height, "name": cname, "ts": time.time()}
    return {"ok": True, "key": key, "size": size, "height": height, "name": cname,
            "cached": False, "secs": round(time.time() - t0, 1),
            "orig": int(orig_size or 0)}


def _is_mp4(path):
    """看前 12 字节有没有 ftyp 盒，挡掉 ffmpeg 失败但留下半截文件的情况"""
    try:
        with open(path, "rb") as f:
            head = f.read(12)
        return len(head) >= 12 and head[4:8] == b"ftyp"
    except OSError:
        return False


def _rm(p):
    try:
        os.remove(p)
    except OSError:
        pass


_GATE_HTML = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>需要访问口令</title><style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
 background:#0f1115;color:#e6e8ee;font:15px/1.7 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
.b{max-width:520px;padding:36px 32px;border:1px solid #262b36;border-radius:16px;background:#161a21}
h1{margin:0 0 14px;font-size:19px;font-weight:600}
code{background:#0f1115;border:1px solid #262b36;border-radius:6px;padding:1px 6px;color:#7dd3fc}
p{margin:10px 0;color:#9aa4b2}ol{color:#9aa4b2;padding-left:20px}
</style></head><body><div class="b">
<h1>需要访问口令</h1>
<p>这个服务开了访问口令校验。用带 <code>?k=口令</code> 的完整地址打开一次，之后浏览器会记住（cookie 30 天）。</p>
<ol><li>向部署的人要口令（或看服务端启动时打印的那一行「口令」）</li>
<li>地址栏改成 <code>http://本机地址:端口/?k=口令</code></li></ol>
<p>只想本机用、不想要口令：用 <code>--host 127.0.0.1</code> 重启（默认就是这个）。</p>
</div></body></html>"""


# ---------------------------------------------------------------- 基础
def device_id(sess):
    """uwx 设备指纹，进程级缓存（首取失败则用本地降级格式）"""
    global _UWX
    if _UWX is None:
        _UWX = H.uwx_id(sess)
    return _UWX


# 平台判定 / 体积解析 / 探测 / 换链只有 hellotik_dl.py 一份实现，WebUI 直接复用
detect = H.detect_platform
total_size = H.total_size

PROXY_TTL = 300                     # 换链结果缓存 5 分钟（顶链会过期，太长会拿到死链）
_PROXY = {}                         # src -> (proxy_url, ts)


def proxy_of(src, referer):
    """换站内代理直链（无 cookie 依赖，可并发）；带 TTL 缓存。
    原来每次 /api/file、/api/compress 都重新换一次链，同一档位重复点几次就多几十个请求。"""
    now = time.time()
    with _LOCK:
        hit = _PROXY.get(src)
        if hit and now - hit[1] < PROXY_TTL:
            return hit[0]
    px = H.proxy_url_stateless(src, referer)
    if px:
        with _LOCK:
            _PROXY[src] = (px, now)
            if len(_PROXY) > 512:            # 简单容量控制：先丢最老的
                for k, _ in sorted(_PROXY.items(), key=lambda kv: kv[1][1])[:128]:
                    _PROXY.pop(k, None)
    return px


def measure_one(src, referer, timeout=45):
    """换链 + 一次探测拿 status/size/dim（原先是 HEAD + GET + 两次 GET 共 3~4 个请求）"""
    px = src if direct_src(src) else proxy_of(src, referer)
    if not px:
        return {"status": 0, "size": 0, "dim": None, "proxy": None}
    m = H.measure(px, referer, timeout=timeout)
    m["proxy"] = px
    return m


def quality_label(src, known_type=None):
    return H.quality_label(src, known_type)


def allowed(u):
    try:
        host = (urllib.parse.urlparse(u).hostname or "").lower()
    except Exception:
        return False
    if not host or host.replace(".", "").isdigit():
        return False
    return any(host.endswith(s) for s in ALLOW_SUFFIX)


def direct_src(u):
    """snapcdn 这类地址本身即下载代理（服务端替我们回源 twimg），直接用，不再换链"""
    try:
        host = (urllib.parse.urlparse(u).hostname or "").lower()
    except Exception:
        return False
    return any(host.endswith(s) for s in DIRECT_SUFFIX)


# ---------------------------------------------------------------- X（推特）
def _strip_tag(s):
    s = re.sub(r"<[^>]+>", " ", s or "")
    return re.sub(r"\s+", " ", htmlmod.unescape(s)).strip()


def x_canon(url):
    """任意 x/twitter 链接 → (https://x.com/<user>/status/<id>, id)"""
    m = re.search(X_RX, url)
    tid = m.group(1) if m else None
    if not tid:
        m2 = re.search(r"status(?:es)?/(\d{10,25})", url)
        tid = m2.group(1) if m2 else None
    if not tid:
        return None, None
    u = re.search(r"(?:x\.com|twitter\.com)/([A-Za-z0-9_]{1,20})/status", url)
    return "https://x.com/%s/status/%s" % (u.group(1) if u else "i", tid), tid


def _jwt_payload(tok):
    try:
        p = tok.split(".")[1].replace("-", "+").replace("_", "/")
        return json.loads(base64.b64decode(p + "=" * (-len(p) % 4)).decode("utf-8", "replace"))
    except Exception:
        return {}


def x_search(url):
    """x2twitter / savetwitter 的 ajaxSearch（同一个 snapcdn 后端，互为备份）→ HTML"""
    q = x_canon(url)[0] or url
    body = urllib.parse.urlencode({"q": q, "lang": "en"}).encode()
    last = None
    for base in X_BASES:
        req = urllib.request.Request(base + "/api/ajaxSearch", data=body, method="POST")
        req.add_header("content-type", "application/x-www-form-urlencoded")
        req.add_header("x-requested-with", "XMLHttpRequest")
        req.add_header("origin", base)
        req.add_header("referer", base + "/en")
        req.add_header("user-agent", H.UA)
        req.add_header("accept", "application/json, text/javascript, */*; q=0.01")
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                j = json.loads(r.read().decode("utf-8", "replace"))
            h = j.get("data") or ""
            if j.get("status") == "ok" and h.strip():
                return h, None
            msg = j.get("msg") or j.get("message")
            if j.get("statusCode") == 404 or (msg and "not found" in msg.lower()):
                return None, "这条推文没有可下载的视频（可能已删除、私密，或本身不含视频）"
            last = msg or j.get("status") or "接口未返回数据"
        except Exception as e:
            last = "%s 请求失败: %s" % (base, e)
    return None, last


def x_items(html):
    """解析 ajaxSearch 返回的 HTML → (推文正文, [{media, cover, entries}])"""
    title = ""
    m = re.search(r"<h3[^>]*>(.*?)</h3>", html, re.S)
    if m:
        title = _strip_tag(m.group(1))
    blocks = re.findall(r'class="tw-video">(.*?)(?=class="tw-video">|$)', html, re.S) or [html]
    items = []
    for bi, blk in enumerate(blocks, 1):
        cov = re.search(r'<img[^>]*src="([^"]+)"', blk)
        cover = htmlmod.unescape(cov.group(1)) if cov else None
        entries = []
        for a in re.finditer(
                r'<a[^>]*href="(https://[^"]*snapcdn\.app/get\?token=[^"]+)"[^>]*>(.*?)</a>', blk, re.S):
            link, inner = htmlmod.unescape(a.group(1)), _strip_tag(a.group(2))
            pay = _jwt_payload(link.split("token=")[-1])
            real = pay.get("url") or ""
            fn = pay.get("filename") or ""
            qm = re.search(r"\(([^)]+)\)", inner)
            dm = re.search(r"/vid/(?:[a-z0-9]+/)?(\d+x\d+)/", real)
            entries.append({
                "label": qm.group(1) if qm else (dm.group(1) if dm else "档位"),
                "src": link, "real": real, "filename": fn,
                "dims": dm.group(1) if dm else None,
                "kind": "video" if (".mp4" in fn.lower() or "/vid/" in real) else "photo",
            })
        mid = ""
        for e in entries:
            mm = re.search(r"/(?:ext_tw_video|amplify_video|tweet_video)/(\d+)", e["real"])
            if mm:
                mid = mm.group(1)
                break
        if not mid:
            mm = re.search(r"/(?:ext_tw_video_thumb|amplify_video_thumb|tweet_video_thumb)/(\d+)",
                           cover or "")
            mid = mm.group(1) if mm else "m%d" % bi
        items.append({"media": mid, "cover": cover, "entries": entries})
    return title, items


def x_cover(item):
    """pbs.twimg.com 本机不可达：改用同一媒体的 snapcdn 图片直链当封面"""
    base = os.path.basename(item.get("cover") or "")
    if base:
        for e in item["entries"]:
            if base in (e["real"] + e["filename"]):
                return e["src"]
    for e in item["entries"]:
        if e["kind"] == "photo":
            return e["src"]
    return None


def x_fxmeta(url):
    """尽力而为：fxtwitter 元数据（作者 + 每条媒体时长），失败不影响解析"""
    _, tid = x_canon(url)
    if not tid:
        return {}
    try:
        req = urllib.request.Request("https://api.fxtwitter.com/i/status/" + tid)
        req.add_header("user-agent", H.UA)
        with urllib.request.urlopen(req, timeout=12) as r:
            tw = (json.loads(r.read().decode("utf-8", "replace")) or {}).get("tweet") or {}
        out = {"author": (tw.get("author") or {}).get("screen_name"), "dur": {}}
        for v in ((tw.get("media") or {}).get("videos") or []):
            mm = re.search(r"/(?:ext_tw_video|amplify_video|tweet_video)/(\d+)", v.get("url") or "")
            if mm:
                out["dur"][mm.group(1)] = v.get("duration")
        return out
    except Exception:
        return {}


def _x_ytdlp_phase(url, alt, t0):
    """x2twitter 不可用时的 yt-dlp 兜底：直链由本机（或代理）直接出网，不经过 snapcdn"""
    cands = alt["candidates"]
    best = alt.get("best") or 0
    sid = secrets.token_urlsafe(12)
    with _LOCK:
        SESSIONS[sid] = {"sess": None, "url": url, "payload": None, "page_path": "",
                         "ts": time.time(), "x": cands}
        for k in [k for k, v in SESSIONS.items() if time.time() - v["ts"] > SESS_TTL]:
            SESSIONS.pop(k, None)
    return {"ok": True, "sid": sid, "platform": "x", "complete": True,
            "title": (("@" + str(alt["author"]) + " · ") if alt.get("author") else "")
                     + (alt.get("title") or "X 视频"),
            "type": "video", "cover": alt.get("cover") or "", "qualityTier": None,
            "candidates": cands, "best": best, "moreAvailable": False, "linkTtl": None,
            "engine": "yt-dlp",
            "timing": {"parse": round(time.time() - t0, 2)}}


def x_phase(url):
    """X（推特）：元数据走第三方接口，文件走 dl.snapcdn.app 代理——本机不需要连上 X。
    第三方不可用时回退到本机 yt-dlp（需要能出网/配代理）。"""
    t0 = time.time()
    html, err = x_search(url)
    if not html:
        alt = H.x_from_ytdlp(url, timeout=int(os.environ.get("X_YTDLP_TIMEOUT") or 90))
        if alt.get("ok"):
            return _x_ytdlp_phase(url, alt, t0)
        why = err or "未知错误"
        if not H.ytdlp_bin():
            why += "；" + H.YTDLP_HINT
        return {"ok": False, "stage": "xparse", "platform": "x",
                "error": "X 解析失败：%s" % why, "error_code": "X_SEARCH_FAILED"}
    title, items = x_items(html)
    vids = [it for it in items if any(e["kind"] == "video" for e in it["entries"])]
    if not vids:
        return {"ok": False, "stage": "xparse", "platform": "x",
                "error": "这条推文里没有视频", "error_code": "X_NO_VIDEO"}
    fx = x_fxmeta(url)
    n = len(vids)
    flat = []
    for vi, it in enumerate(vids, 1):
        es = [e for e in it["entries"] if e["kind"] == "video"]
        es.sort(key=lambda e: -int(re.sub(r"\D", "", e["label"]) or 0))
        for e in es:
            flat.append((vi, it, e))
    with ThreadPoolExecutor(max_workers=8) as ex:
        sizes = list(ex.map(lambda t: measure_one(t[2]["src"], H.BASE + "/zh/douyin"), flat))
    cands = []
    for (vi, it, e), s in zip(flat, sizes):
        lab = e["label"] if n <= 1 else "%s（视频 %d）" % (e["label"], vi)
        cands.append({"label": lab, "src": e["src"], "proxy": e["src"], "real": e["real"],
                      "size": s["size"], "dim": e["dims"], "status": s["status"], "source": "x",
                      "duration": (fx.get("dur") or {}).get(it["media"])})
    cands.sort(key=lambda c: (-(c["size"] or 0), str(c["label"])))
    best = H.pick_best(cands)
    sid = secrets.token_urlsafe(12)
    with _LOCK:
        SESSIONS[sid] = {"sess": None, "url": url, "payload": None, "page_path": "",
                         "ts": time.time(), "x": cands}
        for k in [k for k, v in SESSIONS.items() if time.time() - v["ts"] > SESS_TTL]:
            SESSIONS.pop(k, None)
    ttl = _jwt_payload(cands[0]["src"].split("token=")[-1]).get("exp") if cands else None
    return {"ok": True, "sid": sid, "platform": "x", "complete": True,
            "title": (("@" + str(fx["author"]) + " · ") if fx.get("author") else "")
                     + (title or "X 视频"),
            "type": "video", "cover": x_cover(vids[0]), "qualityTier": None,
            "candidates": cands, "best": best, "moreAvailable": False, "linkTtl": ttl,
            "timing": {"parse": round(time.time() - t0, 2)}}


# ---------------------------------------------------------------- 阶段一
def phase_parse(url):
    """gate + parse：秒级返回标题/封面/基础档位"""
    t0 = time.time()
    platform, page_path = detect(url)
    if platform == "x" and not FIXTURE_MODE:
        return x_phase(url)
    if FIXTURE_MODE:
        time.sleep(1.2)
        if FIXTURE_FAIL:
            return {"ok": False, "stage": "gate", "httpStatus": 429,
                    "error": "站方限流，稍等十几秒再点一次（当前请求暂时无法处理，请稍后再试。）",
                    "error_code": "TICKET_IP_RESTRICTED", "platform": platform}
        sid = "fixture-" + secrets.token_urlsafe(6)
        cands = [{"label": l, "src": "https://v26-kefu.douyinvod.com/example/%s.mp4" % l,
                  "proxy": "https://data.hellotik.app/v1/download/video?token=fixture", "size": s,
                  "dim": d, "source": "parse", "status": 200}
                 for l, s, d in FIXTURE["phase1"]]
        return {"ok": True, "sid": sid, "platform": FIXTURE["platform"],
                "title": FIXTURE["title"], "type": FIXTURE["type"],
                "cover": "https://p95-zjwztc-sign.douyinpic.com/fixture.jpg",
                "qualityTier": FIXTURE["qualityTier"], "candidates": cands,
                "moreAvailable": True, "fixture": True,
                "timing": {"parse": round(time.time() - t0, 2)}}
    sess = H.Session()
    r = H.parse(sess, url, uwx_id=device_id(sess), page_path=page_path)
    if not r.get("ok"):
        src = r.get("raw") or r.get("gate") or {}
        receipt = (r.get("raw") or {}).get("_ops_parse_receipt") or {}
        st = r.get("httpStatus")
        msg = (src.get("message") or src.get("error") or src.get("reason")
               or r.get("error") or "解析失败")
        code = receipt.get("error_code") or src.get("code") or src.get("error_code")
        if st == 429 or code in ("rate_limited", "RATE_LIMITED"):
            msg = "站方限流，稍等十几秒再点一次（%s）" % msg
        return {
            "ok": False,
            "stage": r.get("stage"),
            "httpStatus": st,
            "error": msg,
            "error_code": code,
            "detail": src if r.get("stage") == "gate" else None,
            "platform": platform,
        }
    p = r["payload"]
    info = (p.get("videos") or [{}])[0]
    cands = []
    for v in info.get("video_fullinfo", []) or []:
        if v.get("url"):
            cands.append({"label": v.get("type") or "—", "src": v["url"], "proxy": None,
                          "size": int(v.get("size") or 0), "dim": None,
                          "source": "parse", "status": 0})
    cands.sort(key=lambda c: -c["size"])
    sid = secrets.token_urlsafe(12)
    with _LOCK:
        SESSIONS[sid] = {"sess": sess, "url": url, "payload": p, "page_path": page_path,
                         "ts": time.time()}
        for k in [k for k, v in SESSIONS.items() if time.time() - v["ts"] > SESS_TTL]:
            SESSIONS.pop(k, None)
    token = p.get("moreSizeToken")
    return {
        "ok": True, "sid": sid, "platform": platform,
        "title": p.get("title"), "type": p.get("type"), "cover": p.get("cover"),
        "qualityTier": r.get("qualityTier"),
        "candidates": cands,
        "moreAvailable": bool(token),
        "timing": {"parse": round(time.time() - t0, 2)},
    }


# ---------------------------------------------------------------- 阶段二
def phase_more(sid):
    """more-size 更高码率 + 并发探测每档体积/分辨率"""
    t0 = time.time()
    if FIXTURE_MODE:
        time.sleep(3.5)
        cands = [{"label": l, "src": "https://v26-colds.douyinvod.com/example/%s.mp4" % l,
                  "proxy": "https://data.hellotik.app/v1/download/video?token=fixture", "size": s,
                  "dim": d, "source": "more-size" if l in ("原始档", "1109kbps") else "parse",
                  "status": 200}
                 for l, s, d in FIXTURE["phase2"]]
        return {"ok": True, "candidates": cands, "best": 0, "moreSizeError": None,
                "timing": {"probe": round(time.time() - t0, 2)}}
    ent = SESSIONS.get(sid)

    if ent and ent.get("x"):                     # X：各档位在阶段一就已取全，无需二次追取
        xs = ent["x"]
        return {"ok": True, "candidates": xs, "best": H.pick_best(xs),
                "moreSizeError": None, "timing": {"probe": 0}}
    if not ent:
        return {"ok": False, "error": "会话不存在或已过期，请重新解析"}
    sess, url, p = ent["sess"], ent["url"], ent["payload"]
    referer = sess.referer
    token = p.get("moreSizeToken")
    more_error = None

    pool = {}
    info = (p.get("videos") or [{}])[0]
    for v in info.get("video_fullinfo", []) or []:
        if v.get("url"):
            pool[v["url"]] = {"label": v.get("type"), "sizeHint": int(v.get("size") or 0),
                              "source": "parse"}
    if info.get("url"):
        pool.setdefault(info["url"], {"label": None, "sizeHint": 0, "source": "parse"})

    if token:
        ms = H.more_size(sess, url, token)
        if ms.get("ok"):
            d = ms["data"]
            if d.get("url"):
                pool[d["url"]] = {"label": "原始档", "sizeHint": 0, "source": "more-size"}
            for v in d.get("variants", []) or []:
                if v.get("url"):
                    pool.setdefault(v["url"], {"label": None, "sizeHint": 0, "source": "more-size"})
        else:
            j = ms.get("raw") or {}
            more_error = (j.get("message") or j.get("error") or j.get("reason")
                          or ("HTTP %s" % ms.get("httpStatus")))

    cands = [{"label": c["label"] or quality_label(s), "src": s, "proxy": None,
              "size": c["sizeHint"], "dim": None, "source": c["source"], "status": 0}
             for s, c in pool.items()]

    # 换链 + 体积/分辨率一次探测，整批并发（原来是每档 3~4 个请求 + 嵌套线程池）
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(cands)))) as ex:
        ms = list(ex.map(lambda c: measure_one(c["src"], referer), cands))
    for c, m in zip(cands, ms):
        c["size"] = m.get("size") or c["size"]
        c["status"] = m.get("status") or 0
        c["dim"] = m.get("dim")
        c["proxy"] = m.get("proxy")

    cands = H.dedupe_by_size(cands)              # 同体积视为同一文件
    best = H.pick_best(cands)
    return {"ok": True, "candidates": cands, "best": best, "moreSizeError": more_error,
            "timing": {"probe": round(time.time() - t0, 2)}}


def phase_resolve(url):
    a = phase_parse(url)
    if not a.get("ok"):
        return a
    b = phase_more(a["sid"]) if a.get("moreAvailable") else {"ok": True, "candidates": [], "best": None}
    if not b.get("ok"):
        return a
    uniq = H.dedupe_by_size(b.get("candidates") or a["candidates"])
    a["candidates"] = uniq
    a["best"] = H.pick_best(uniq)
    a["moreSizeError"] = b.get("moreSizeError")
    a["timing"] = {"parse": a["timing"]["parse"], "probe": b["timing"]["probe"]}
    return a


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "hellotik-webui/1.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        sys.stderr.write("[webui] %s %s\n" % (self.address_string(), fmt % a))

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(body)

    # ---------- 访问控制 ----------
    def _client_ip(self):
        return self.client_address[0] if self.client_address else "?"

    def _rate_ok(self):
        if ACCESS_TOKEN is None:
            return True
        ip = self._client_ip()
        now = time.time()
        with _LOCK:
            win, n = _RATE.get(ip, (now, 0))
            if now - win >= 60:
                win, n = now, 0
            n += 1
            _RATE[ip] = (win, n)
            return n <= RATE_LIMIT

    def _gate(self, parsed):
        """口令校验；未通过时直接回 401/429 并返回 False。"""
        if ACCESS_TOKEN is None:
            return True
        if not self._rate_ok():
            self._send(429, {"error": "请求过于频繁，请稍后再试"})
            return False
        q = urllib.parse.parse_qs(parsed.query)
        cookie = ""
        for part in (self.headers.get("cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE_NAME:
                cookie = v
        given = cookie or (q.get("k", [""])[0])
        if not hmac.compare_digest(given, ACCESS_TOKEN or ""):
            if parsed.path in ("/", "/index.html"):
                return self._send(401, _GATE_HTML, "text/html; charset=utf-8")
            return self._send(401, {"error": "缺少或错误的口令：在地址后面加上 ?k=<口令>"})
        return True

    # ---------- GET ----------
    def do_HEAD(self):
        self._head_only = True
        self.do_GET()

    def _range(self, size):
        """解析单段 Range。返回 (status, start, end)；None = 不可满足（回 416）。
        浏览器 <video> 拖动进度条、断点续传都靠它，原实现一律 200 整文件。"""
        rng = (self.headers.get("range") or "").strip()
        if not rng:
            return 200, 0, size - 1
        m = re.fullmatch(r"bytes=(\d*)-(\d*)", rng)
        if not m or (not m.group(1) and not m.group(2)):
            return None
        if m.group(1):
            begin = int(m.group(1))
            last = int(m.group(2)) if m.group(2) else size - 1
        else:
            n = int(m.group(2))
            begin, last = max(0, size - n), size - 1
        if begin >= size or begin > last:
            return None
        return 206, begin, min(last, size - 1)

    def do_GET(self):
        gc()
        u = urllib.parse.urlparse(self.path)
        if not self._gate(u):
            return
        q = urllib.parse.parse_qs(u.query)
        # 用 ?k= 进来的：种下 cookie，后续下载链接（a[href] 带不了 query）也能通
        extra = None
        if ACCESS_TOKEN and q.get("k", [""])[0] == ACCESS_TOKEN:
            extra = {"set-cookie": "%s=%s; Path=/; Max-Age=2592000; SameSite=Lax"
                                   % (COOKIE_NAME, ACCESS_TOKEN)}
        if u.path in ("/", "/index.html"):
            try:
                with open(INDEX, "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8", extra)
            except OSError as e:
                return self._send(500, {"error": "index.html 读取失败: %s" % e})
        if u.path == "/api/file":
            return self.download(q)
        if u.path == "/api/cfile":
            return self.cfile(q)
        if u.path == "/api/img":
            return self.image(q)
        if u.path == "/api/status":
            return self._send(200, {"ok": True, "platforms": [p[0] for p in PLATFORMS],
                                    "sessions": len(SESSIONS), "uwx_id": _UWX,
                                    "auth": ACCESS_TOKEN is not None,
                                    "ffmpeg": bool(FFMPEG),
                                    "ytdlp": bool(H.ytdlp_bin()),
                                    "presets": sorted(COMPRESS_PRESETS, key=int, reverse=True),
                                    "cached": len([f for f in os.listdir(CACHE_DIR)
                                                   if f.endswith(".mp4")])
                                              if os.path.isdir(CACHE_DIR) else 0,
                                    "host": self.headers.get("host")})
        return self._send(404, {"error": "not found"})

    def cfile(self, q):
        """下发已压缩好的文件（结果按 key 缓存）；支持 Range，可边下边播。"""
        key = (q.get("key") or [""])[0]
        if not re.fullmatch(r"[0-9a-f]{16}", key):
            return self._send(400, {"error": "非法 key"})
        meta = _COMP_DONE.get(key)
        path = os.path.join(CACHE_DIR, "%s.mp4" % key)
        if not os.path.isfile(path):
            return self._send(404, {"error": "压缩结果不存在或已被清理"})
        size = os.path.getsize(path)
        rg = self._range(size)
        if rg is None:
            return self._send(416, {"error": "range 不可满足"},
                              extra={"content-range": "bytes */%d" % size})
        st, begin, last = rg
        name = (q.get("name") or [""])[0] or (meta or {}).get("name") or "video_压缩.mp4"
        name = re.sub(r"[\\/:*?\"<>|\r\n]+", "_", name)
        self.send_response(st)
        self.send_header("content-type", "video/mp4")
        self.send_header("content-length", str(last - begin + 1))
        self.send_header("accept-ranges", "bytes")
        if st == 206:
            self.send_header("content-range", "bytes %d-%d/%d" % (begin, last, size))
        self.send_header("content-disposition",
                         "attachment; filename*=UTF-8''" + urllib.parse.quote(name))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        if getattr(self, "_head_only", False):
            return
        try:
            with open(path, "rb") as f:
                f.seek(begin)
                left = last - begin + 1
                while left > 0:
                    block = f.read(min(256 * 1024, left))
                    if not block:
                        break
                    self.wfile.write(block)
                    left -= len(block)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try:
                self._send(500, {"error": "下发失败: %s" % e})
            except Exception:
                pass

    def download(self, q):
        src = (q.get("u") or [""])[0]
        name = (q.get("name") or ["video.mp4"])[0]
        if FIXTURE_MODE:
            fake = b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00isomiso2avc1mp41" + b"\x00" * 64
            return self._send(200, fake, "video/mp4",
                              {"content-disposition":
                               "attachment; filename*=UTF-8''" + urllib.parse.quote(name),
                               "accept-ranges": "bytes"})
        if not src or not allowed(src):
            return self._send(400, {"error": "非白名单源站，拒绝代理"})
        _, page_path = detect(src)
        target = src if direct_src(src) else proxy_of(src, H.BASE + page_path)
        if not target:
            return self._send(502, {"error": "换链失败"})
        hdr = {"user-agent": H.UA, "accept": "*/*"}
        if not direct_src(src):
            hdr["referer"] = H.BASE + page_path
        rng = self.headers.get("range")
        if rng:
            hdr["range"] = rng                      # 把客户端的 Range 透传给源站
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(target, headers=hdr), timeout=120) as r:
                st = 206 if (rng and r.status == 206) else 200
                self.send_response(st)
                self.send_header("content-type", r.headers.get("content-type") or "video/mp4")
                if st == 206 and r.headers.get("content-range"):
                    self.send_header("content-range", r.headers["content-range"])
                cl = r.headers.get("content-length")
                if cl:
                    self.send_header("content-length", cl)
                self.send_header("accept-ranges", "bytes")
                self.send_header("content-disposition",
                                 "attachment; filename*=UTF-8''" + urllib.parse.quote(name))
                self.send_header("cache-control", "no-store")
                self.end_headers()
                if getattr(self, "_head_only", False):
                    return
                shutil.copyfileobj(r, self.wfile, 256 * 1024)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try:
                self._send(502, {"error": "下载失败: %s" % e})
            except Exception:
                pass

    def image(self, q):
        src = (q.get("u") or [""])[0]
        if FIXTURE_MODE:
            return self._send(200, _PNG_1PX, "image/png", {"cache-control": "no-store"})
        if not src or not allowed(src):
            return self._send(400, {"error": "非白名单源站"})
        _, page_path = detect(src)
        hdr = {"user-agent": H.UA, "accept": "image/*,*/*"}
        if not direct_src(src):
            hdr["referer"] = H.BASE + page_path
        req = urllib.request.Request(src, headers=hdr)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return self._send(200, r.read(),
                                  r.headers.get("content-type", "image/jpeg"),
                                  {"cache-control": "max-age=600"})
        except Exception as e:
            return self._send(502, {"error": "封面获取失败: %s" % e})

    # ---------- POST ----------
    MAX_BODY = 64 * 1024

    def _read_body(self):
        """请求体先读干净再鉴权：否则 401 提前返回会把 body 留在连接里，keep-alive 串包。"""
        try:
            n = int(self.headers.get("content-length") or 0)
        except ValueError:
            self.close_connection = True
            return None
        if n < 0 or n > self.MAX_BODY:
            self.close_connection = True
            return None
        return self.rfile.read(n) if n else b""

    def do_POST(self):
        gc()
        parsed = urllib.parse.urlparse(self.path)
        raw = self._read_body()
        if raw is None:
            return self._send(413, {"ok": False, "error": "请求体过大或 Content-Length 非法"})
        if not self._gate(parsed):
            return
        path = parsed.path
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            body = {}
        if path in ("/api/parse", "/api/resolve"):
            url = H.extract_url(str(body.get("url") or "")) or str(body.get("url") or "").strip()
            if not re.match(r"^https?://", url):
                return self._send(400, {"ok": False, "error": "请填写 http(s) 分享链接"})
            fn = phase_parse if path == "/api/parse" else phase_resolve
            try:
                return self._send(200, fn(url))
            except Exception as e:
                return self._send(500, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
        if path == "/api/more":
            sid = str(body.get("sid") or "")
            try:
                return self._send(200, phase_more(sid))
            except Exception as e:
                return self._send(500, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
        if path == "/api/compress":
            if FIXTURE_MODE:
                return self._send(200, {"ok": True, "key": "0" * 16, "size": 1234567,
                                        "height": str(body.get("height") or "720"),
                                        "name": "示例数据_压缩.mp4", "cached": False, "secs": 3.2,
                                        "orig": int(body.get("orig") or 0)})
            src = str(body.get("src") or "").strip()
            if not re.match(r"^https?://", src):
                return self._send(400, {"ok": False, "error": "缺少有效的源地址"})
            try:
                return self._send(200, compress_video(src, str(body.get("name") or "video.mp4"),
                                                      str(body.get("height") or "720"),
                                                      body.get("orig") or 0,
                                                      str(body.get("vid") or "")))
            except Exception as e:
                return self._send(500, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
        return self._send(404, {"error": "not found"})


def main():
    global FIXTURE_MODE, FIXTURE_FAIL, ACCESS_TOKEN, FFMPEG
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default=None,
                    help="监听地址；--public 时默认 0.0.0.0，否则 127.0.0.1")
    ap.add_argument("--public", action="store_true",
                    help="挂到局域网：监听 0.0.0.0 并强制访问口令（未给 --token 则自动生成）")
    ap.add_argument("--token", default=None,
                    help="访问口令；给了就开启校验（地址后加 ?k=口令，或首次访问自动种 cookie）")
    ap.add_argument("--fixture", action="store_true",
                    help="演示模式：用一条真实抓取结果回放，不请求站方接口（验证界面用）")
    ap.add_argument("--fixture-fail", action="store_true",
                    help="配合 --fixture：回放站方限流报错，用来验证错误提示与冷却倒计时")
    ap.add_argument("--no-compress", action="store_true",
                    help="禁用压缩功能（即使装了 ffmpeg 也不启用）")
    a = ap.parse_args()
    for stream in (sys.stdout, sys.stderr):   # Windows 控制台中文别花屏
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    FIXTURE_MODE = a.fixture
    FIXTURE_FAIL = a.fixture_fail
    FFMPEG = None if a.no_compress else find_ffmpeg()
    token = a.token
    if a.public and not token:
        token = secrets.token_urlsafe(9)
    ACCESS_TOKEN = token
    host = a.host or ("0.0.0.0" if a.public else "127.0.0.1")
    srv = ThreadingHTTPServer((host, a.port), Handler)
    srv.daemon_threads = True
    tag = "  [fixture 演示模式%s]" % ("·限流报错" if FIXTURE_FAIL else "") if FIXTURE_MODE else ""
    print("hellotik WebUI%s" % tag, flush=True)
    print("  本机   http://127.0.0.1:%d%s" % (a.port, ("/?k=" + token) if token else ""), flush=True)
    if host != "127.0.0.1":
        for ip in lan_ips():
            print("  局域网 http://%s:%d%s" % (ip, a.port, ("/?k=" + token) if token else ""), flush=True)
        if not token:
            print("  ⚠ 无口令，局域网内任何人都能用；建议加 --token", flush=True)
    print("  口令   %s" % (token if token else "（未启用，仅本机模式）"), flush=True)
    print("  压缩   %s" % ("ffmpeg 已就绪 -> %s（目标 %s）"
                           % (FFMPEG, "/".join(sorted(COMPRESS_PRESETS, key=int, reverse=True)))
                           if FFMPEG else "未找到 ffmpeg，压缩按钮会提示不可用"
                           + "（放到 bin/ffmpeg.exe 或加进 PATH 即可启用）"), flush=True)
    if host != "127.0.0.1":
        print("  防火墙 放行（管理员 PowerShell 执行一次）:", flush=True)
        print("    New-NetFirewallRule -DisplayName hellotik-WebUI -Direction Inbound "
              "-Protocol TCP -LocalPort %d -Action Allow" % a.port, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
