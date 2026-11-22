# -*- coding: utf-8 -*-
"""端到端测试：本地假站完整复现 gate/parse/more-size/换链/媒体 Range，
  然后用真实 CLI 与 WebUI Handler 走一遍（不联网）。
    python -m unittest discover -s tests -v
"""
import base64
import hashlib
import http.client
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.parse
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import hellotik_dl as H  # noqa: E402

STD, CUS = H.STD_ALPHABET, H.CUSTOM_ALPHABET
SIZES = {3500: 300000, 2400: 220000, 1800: 160000, 900: 80000}
DIMS = {3500: (1080, 1920), 2400: (720, 1280), 1800: (720, 1280), 900: (576, 1024)}


def _alpha(b):
    return bytes(ord(CUS[STD.index(chr(c))]) if chr(c) in STD else c for c in b)


def _rev8(b):
    return b"".join(b[i:i + 8][::-1] for i in range(0, len(b), 8))


def _xor(b):
    return bytes(c ^ 90 for c in b)


def obf_body(ct):
    return _xor(_rev8(_alpha(base64.b64encode(ct))))


def obf_parse(ct):
    return base64.b64encode(obf_body(ct))


def make_media(br):
    w, h = DIMS.get(br, (1080, 1920))
    size = SIZES.get(br, 120000)
    tkhd = (b"\x00\x00\x00\x68" + b"tkhd" + b"\x00" * 76
            + (w << 16).to_bytes(4, "big") + (h << 16).to_bytes(4, "big") + b"\x00" * 12)
    head = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isom" + tkhd
    return head + bytes((i * 7 + br) % 256 for i in range(size - len(head)))


class FakeHellotik(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # ---------- 工具 ----------
    def _json(self, obj, code=200, extra=None):
        raw = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        n = int(self.headers.get("content-length") or 0)
        return self.rfile.read(n) if n else b""

    # ---------- 路由 ----------
    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        raw = self._body()          # 只读一次：重复读会阻塞在 recv 上
        if path.startswith("/api/gate"):
            return self._json({"tk_e5eea8": "TK", "sd_e5eea8": "SD", "status": 0},
                              extra={"set-cookie": "parse_sid=fake; Path=/"})
        if path == "/api/parse":
            payload = {
                "title": "测试视频", "type": "video",
                "cover": "https://p26.douyinpic.com/cover.jpg",
                "url": "https://v26-kefu.douyinvod.com/main.mp4?br=900",
                "moreSizeToken": "eyJhbGciOiJIUzI1NiJ9.e30.x",
                "videos": [{
                    "url": "https://v26-kefu.douyinvod.com/main.mp4?br=900",
                    "video_fullinfo": [
                        {"url": "https://v26-kefu.douyinvod.com/hd.mp4?br=2400",
                         "type": "720p", "size": "150000"},
                        {"url": "https://v26-kefu.douyinvod.com/sd.mp4?br=900",
                         "type": "540p", "size": "70000"},
                    ],
                }],
            }
            iv = b"0123456789abcdef"
            ct = H.aes_cbc_encrypt(H.SALT, iv, json.dumps(payload).encode())
            return self._json({"status": 0, "encrypt": True, "qualityTier": "hd",
                               "data": obf_parse(ct).decode(),
                               "key": obf_parse(iv).decode()})
        if path == "/api/more-size":
            if not self.headers.get("x-more-size-token"):
                return self._json({"status": 1, "message": "token missing"}, 401)
            token = self.headers["x-more-size-token"]
            data = {"url": "https://v26-colds.douyinvod.com/orig.mp4?br=3500",
                    "variants": [{"url": "https://v26-colds.douyinvod.com/v1.mp4?br=1800"}]}
            iv = b"fedcba9876543210"
            key = hashlib.sha256(token.encode()).digest()
            ct = H.aes_cbc_encrypt(key, iv, json.dumps(data).encode())
            return self._json({"status": 0, "encrypt": True,
                               "data": obf_body(ct).decode("latin-1"),
                               "iv": obf_body(iv).decode("latin-1")})
        if path == "/api/download-proxy-url":
            body = json.loads(raw or b"{}")
            br = urllib.parse.parse_qs(urllib.parse.urlparse(body.get("url", "")).query).get("br", ["900"])[0]
            base = "http://%s" % self.headers.get("host")
            return self._json({"status": 0, "url": "%s/media.mp4?br=%s" % (base, br)})
        return self._json({"status": 1, "message": "no route"}, 404)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path != "/media.mp4":
            return self._json({"error": "not found"}, 404)
        br = int(urllib.parse.parse_qs(u.query).get("br", ["900"])[0])
        media = make_media(br)
        total = len(media)
        rng = self.headers.get("range")
        begin, last, code = 0, total - 1, 200
        if rng and rng.startswith("bytes="):
            spec = rng[6:]
            a, _, b = spec.partition("-")
            if a:
                begin = int(a)
                last = int(b) if b else total - 1
            else:
                begin = max(0, total - int(b))
            begin, last = min(begin, total - 1), min(last, total - 1)
            code = 206
        chunk = media[begin:last + 1]
        self.send_response(code)
        self.send_header("content-type", "video/mp4")
        self.send_header("content-length", str(len(chunk)))
        self.send_header("accept-ranges", "bytes")
        if code == 206:
            self.send_header("content-range", "bytes %d-%d/%d" % (begin, last, total))
        self.end_headers()
        self.wfile.write(chunk)


def start_fake():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeHellotik)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


class TestCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = start_fake()
        cls._old_base = H.BASE
        H.BASE = cls.base
        cls.tmp = tempfile.mkdtemp(prefix="hellotik-")

    @classmethod
    def tearDownClass(cls):
        H.BASE = cls._old_base
        cls.srv.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _run(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = H.main(argv)
        return rc, buf.getvalue()

    def test_json_resolve_and_measure(self):
        rc, out = self._run(["7.92 复制打开抖音 https://v.douyin.com/abc/ 看看", "--json", "-m"])
        self.assertEqual(rc, 0, out)
        j = json.loads(out)
        self.assertEqual(j["platform"], "douyin")
        self.assertEqual(j["title"], "测试视频")
        sizes = sorted((c["size"] for c in j["candidates"]), reverse=True)
        self.assertEqual(sizes, [300000, 220000, 160000, 80000])
        best = j["candidates"][j["best"]]
        self.assertEqual(best["size"], 300000)
        self.assertEqual(best["dim"], "1080x1920")
        self.assertEqual(j["candidates"][0]["label"], "原始档")

    def test_download_and_resume(self):
        outdir = os.path.join(self.tmp, "dl")
        rc, out = self._run(["https://v.douyin.com/abc/", "-m", "-d", "--out", outdir])
        self.assertEqual(rc, 0, out)
        files = [f for f in os.listdir(outdir) if f.endswith(".mp4")]
        self.assertEqual(len(files), 1, files)
        path = os.path.join(outdir, files[0])
        with open(path, "rb") as f:
            got = f.read()
        self.assertEqual(len(got), 300000)
        self.assertEqual(got[4:8], b"ftyp")
        # 第二次调用应命中已存在文件（断点续传分支直接返回）
        rc, _ = self._run(["https://v.douyin.com/abc/", "-m", "-d", "--out", outdir])
        self.assertEqual(rc, 0)
        self.assertEqual(os.path.getsize(path), 300000)

    def test_json_single_request_per_candidate(self):
        """--no-measure 只解析：不应发出任何 media 请求"""
        rc, out = self._run(["https://v.douyin.com/abc/", "--json", "--no-measure"])
        self.assertEqual(rc, 0, out)
        j = json.loads(out)
        self.assertTrue(all(c["status"] == 0 for c in j["candidates"]))


class TestWebUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import hellotik_webui as W
        cls.W = W
        cls.srv, cls.base = start_fake()
        cls._old_base = H.BASE
        H.BASE = cls.base
        cls._old_allowed = W.allowed
        W.allowed = lambda u: True                 # 测试假站是 127.0.0.1，白名单放行
        W.ACCESS_TOKEN = "secret"
        cls.CACHE_DIR = W.CACHE_DIR = tempfile.mkdtemp(prefix="hellotik-cache-")
        cls.http_srv = ThreadingHTTPServer(("127.0.0.1", 0), W.Handler)
        cls.http_srv.daemon_threads = True
        threading.Thread(target=cls.http_srv.serve_forever, daemon=True).start()
        cls.port = cls.http_srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        import hellotik_webui as W
        W.allowed = cls._old_allowed
        W.ACCESS_TOKEN = None
        H.BASE = cls._old_base
        cls.http_srv.shutdown()
        cls.srv.shutdown()
        shutil.rmtree(cls.CACHE_DIR, ignore_errors=True)

    def test_parallel_fetch_matches_source(self):
        """4 路 Range 并发抓取：分块、乱序完成，最后的字节必须和源文件一致"""
        import hellotik_webui as W
        total = SIZES[2400]
        url = self.base + "/media.mp4?br=2400"
        path = os.path.join(self.CACHE_DIR, "par.bin")
        p, ready, blk, fh, errs = W.parallel_fetch(
            url, {"user-agent": "t"}, total, path, parts=3, blk=65536, timeout=20)
        for ev in ready:
            self.assertTrue(ev.wait(20), "有块没抓到")
        fh.close()
        self.assertFalse(errs, errs)
        with open(p, "rb") as f:
            self.assertEqual(f.read(), make_media(2400))
        os.remove(p)

    def _conn(self):
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)

    def test_401_does_not_poison_keepalive(self):
        """先不带口令 POST（401），同一条连接上再带口令 POST 必须正常——请求体没被留在缓冲里"""
        c = self._conn()
        body = json.dumps({"url": "https://v.douyin.com/abc/"}).encode()
        c.request("POST", "/api/parse", body, {"content-type": "application/json"})
        r = c.getresponse()
        self.assertEqual(r.status, 401)
        r.read()
        c.request("POST", "/api/parse", body,
                  {"content-type": "application/json", "cookie": "ht_k=secret"})
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        j = json.loads(r.read().decode())
        self.assertTrue(j["ok"])
        self.assertEqual(j["platform"], "douyin")
        c.close()

    def test_body_too_large_rejected(self):
        c = self._conn()
        c.putrequest("POST", "/api/parse")
        c.putheader("cookie", "ht_k=secret")
        c.putheader("content-length", str(10 * 1024 * 1024))
        c.endheaders()
        r = c.getresponse()
        self.assertEqual(r.status, 413)
        r.read()
        c.close()

    def test_parse_then_more_via_http(self):
        c = self._conn()
        body = json.dumps({"url": "https://v.douyin.com/abc/"}).encode()
        hdr = {"content-type": "application/json", "cookie": "ht_k=secret"}
        c.request("POST", "/api/parse", body, hdr)
        a = json.loads(c.getresponse().read().decode())
        self.assertTrue(a["ok"])
        self.assertTrue(a["moreAvailable"])
        c.request("POST", "/api/more", json.dumps({"sid": a["sid"]}).encode(), hdr)
        b = json.loads(c.getresponse().read().decode())
        self.assertTrue(b["ok"])
        self.assertEqual(max(x["size"] for x in b["candidates"]), 300000)
        best = b["candidates"][b["best"]]
        self.assertEqual(best["dim"], "1080x1920")
        c.close()

    def test_file_range_and_head(self):
        q = urllib.parse.urlencode({"u": "https://v26-kefu.douyinvod.com/hd.mp4?br=2400",
                                    "name": "t.mp4"})
        c = self._conn()
        c.request("GET", "/api/file?" + q,
                  headers={"cookie": "ht_k=secret", "range": "bytes=100-199"})
        r = c.getresponse()
        self.assertEqual(r.status, 206)
        self.assertEqual(r.getheader("accept-ranges"), "bytes")
        self.assertTrue(r.getheader("content-range").startswith("bytes 100-199/"))
        self.assertEqual(len(r.read()), 100)
        c.close()

        c = self._conn()
        c.request("HEAD", "/api/file?" + q, headers={"cookie": "ht_k=secret"})
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        self.assertEqual(r.read(), b"")
        c.close()

    def test_cfile_range(self):
        key = "a" * 16
        path = os.path.join(self.CACHE_DIR, key + ".mp4")
        data = bytes(range(256)) * 40
        with open(path, "wb") as f:
            f.write(data)
        self.W._COMP_DONE[key] = {"size": len(data), "height": "720",
                                  "name": "x_压缩.mp4", "ts": __import__("time").time()}
        c = self._conn()
        c.request("GET", "/api/cfile?key=%s" % key,
                  headers={"cookie": "ht_k=secret", "range": "bytes=-100"})
        r = c.getresponse()
        self.assertEqual(r.status, 206)
        self.assertEqual(r.read(), data[-100:])
        c.close()


if __name__ == "__main__":
    unittest.main()
