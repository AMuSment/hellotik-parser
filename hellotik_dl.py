#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hellotik.app 抖音 / 小红书 / 快手 无水印解析下载 —— 纯标准库 Python 复现（研究用）

逆向自站点 JS chunk（全部为静态分析所得）：
  chunk 2716 / module 62261 : generateOutput(data, key, salt)           解析响应解密
  chunk 951  / module 60951 : decryptMoreSizeResponse(data, iv, token)  更高码率响应解密
  chunk 4968                : /api/more-size 前端语义（input 必须与解析时逐字节相同）
  chunk 7630                : uwx 设备指纹

链路：
  1. POST /api/gate-e5eea8  {requestURL,isBatch,mode}   -> tk/sd/ex + Set-Cookie: parse_sid
  2. AES-256-GCM(key=SHA256(tk+":"+sd))  body {tk,pl,iv,vr}  -> POST /api/parse
  3. {status:0,encrypt:true,data,key} -> generateOutput() -> {title,url,videos[],cover,moreSizeToken}
  4. POST /api/more-size (X-More-Size-Token) -> decryptMoreSizeResponse() -> 更高码率 variants
  5. POST /api/download-proxy-url {url}  -> data.hellotik.app 代理直链（源 CDN 有 referer 防盗链）
  6. 下载

零第三方依赖：AES-256 / GCM / CBC 由本文件内的纯 Python 实现提供。
AES 走「字节级查表 + 32 位整字轮密钥」实现，比逐比特 GF 乘法快约 20 倍（见 docs/OPTIMIZATION.md）。

用法:
  python hellotik_dl.py <分享链接|分享文案> [选项]

  -m, --more-size      追取站内更高码率（more-size）
  -d, --download       下载最高档到 dl/
      --out DIR        改下载目录（默认 dl/）
      --quality LABEL  指定档位（如 720p / 原始档），默认取体积最大
      --json           机器可读输出（stdout 只有 JSON）
      --no-measure     只解析，不逐档探测真实体积/分辨率（更快）
      --dump-parse     额外打印解密后的原始 payload（调试用）
      --timeout SEC    单请求超时，默认 40
      --concurrency N  并发探测数，默认 6

X（推特）：
  站方不服务 X，本文件对推文链接走本机 yt-dlp（`yt-dlp -J`，只解析不落盘，直链自己下）。
  需要能出网；境内配代理：X_PROXY=http://127.0.0.1:7890（也认 HTTPS_PROXY / ALL_PROXY）。
  可执行文件查找顺序：YTDLP 环境变量 -> PATH -> 仓库 bin/yt-dlp(.exe)。
"""
import argparse
import base64
import functools
import hashlib
import html
import http.cookiejar
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor

BASE = (os.environ.get("HELLOTIK_BASE") or "https://www.hellotik.app").rstrip("/")  # 可指向自建/镜像
SALT = b"93838338562359368888868323563256"  # chunk 2261 硬编码（32 字节 = AES-256 密钥）
CUSTOM_ALPHABET = "ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw9876543210-_"
STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

# 平台判定：三个抖音系平台共用同一套协议，平台只由 Referer 的 pagePath 区分
PLATFORMS = (
    ("x", "/zh/douyin", r"(?:^|//|\.)(?:x\.com|twitter\.com|t\.co)/"),
    ("rednote", "/zh/rednote", r"xiaohongshu|xhslink"),
    ("kuaishou", "/zh/kuaishou", r"kuaishou|chenzhongtech"),
    ("douyin", "/zh/douyin", r"douyin|iesdouyin"),
)
DEFAULT_PAGE_PATH = "/zh/douyin"


# ======================================================================
# 1. 纯 Python AES-256 / AES-CBC / AES-GCM
# ======================================================================
# 有限域乘法只用来建表（256 项，进程内一次），运行期全部走查表。
def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _build_sbox():
    inv = [0] * 256
    for x in range(1, 256):
        for y in range(1, 256):
            if _gmul(x, y) == 1:
                inv[x] = y
                break
    box = [0] * 256
    for x in range(256):
        s = inv[x]
        r = s
        for _ in range(4):
            s = ((s << 1) | (s >> 7)) & 0xFF
            r ^= s
        box[x] = r ^ 0x63
    inv_box = [0] * 256
    for i, v in enumerate(box):
        inv_box[v] = i
    return box, inv_box


SBOX, INV_SBOX = _build_sbox()
SBOX_B, INV_SBOX_B = bytes(SBOX), bytes(INV_SBOX)
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]

# MixColumns / InvMixColumns 的乘法表（运行期只做 16 次查表 + 异或）
_M2 = bytes(_gmul(x, 2) for x in range(256))
_M3 = bytes(_gmul(x, 3) for x in range(256))
_M9 = bytes(_gmul(x, 9) for x in range(256))
_M11 = bytes(_gmul(x, 11) for x in range(256))
_M13 = bytes(_gmul(x, 13) for x in range(256))
_M14 = bytes(_gmul(x, 14) for x in range(256))


def _shift_rows(b):
    return bytes((b[0], b[5], b[10], b[15], b[4], b[9], b[14], b[3],
                  b[8], b[13], b[2], b[7], b[12], b[1], b[6], b[11]))


def _inv_shift_rows(b):
    return bytes((b[0], b[13], b[10], b[7], b[4], b[1], b[14], b[11],
                  b[8], b[5], b[2], b[15], b[12], b[9], b[6], b[3]))


def _mix_columns(b):
    o = bytearray(16)
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = b[i], b[i + 1], b[i + 2], b[i + 3]
        o[i] = _M2[a0] ^ _M3[a1] ^ a2 ^ a3
        o[i + 1] = a0 ^ _M2[a1] ^ _M3[a2] ^ a3
        o[i + 2] = a0 ^ a1 ^ _M2[a2] ^ _M3[a3]
        o[i + 3] = _M3[a0] ^ a1 ^ a2 ^ _M2[a3]
    return bytes(o)


def _inv_mix_columns(b):
    o = bytearray(16)
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = b[i], b[i + 1], b[i + 2], b[i + 3]
        o[i] = _M14[a0] ^ _M11[a1] ^ _M13[a2] ^ _M9[a3]
        o[i + 1] = _M9[a0] ^ _M14[a1] ^ _M11[a2] ^ _M13[a3]
        o[i + 2] = _M13[a0] ^ _M9[a1] ^ _M14[a2] ^ _M11[a3]
        o[i + 3] = _M11[a0] ^ _M13[a1] ^ _M9[a2] ^ _M14[a3]
    return bytes(o)


def _expand_key(key):
    """AES-256 密钥扩展 -> 60 个字（每字 4 字节）"""
    nk, nr = 8, 14
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]                                    # RotWord
            t = [SBOX[b] for b in t]                              # SubWord
            t[0] ^= RCON[i // nk - 1]
        elif i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w


@functools.lru_cache(maxsize=16)
def _round_keys(key):
    """把 60 个字压成 15 个 128 位整数轮密钥（键由 bytes 缓存，同一密钥只算一次）"""
    w = _expand_key(key)
    return tuple(int.from_bytes(bytes(b for col in w[4 * r:4 * r + 4] for b in col), "big")
                 for r in range(15))


class AES:
    """仅 AES-256（Nk=8, Nr=14）；加解密都以 32 位整字为单位，字节级只做 SubBytes 查表。"""
    __slots__ = ("rk",)

    def __init__(self, key):
        key = bytes(key)
        assert len(key) == 32, "AES-256 requires a 32-byte key"
        self.rk = _round_keys(key)

    def _ark(self, blk, rnd):
        return (int.from_bytes(blk, "big") ^ self.rk[rnd]).to_bytes(16, "big")

    def encrypt_int(self, s):
        rk = self.rk
        b = (s ^ rk[0]).to_bytes(16, "big")
        for rnd in range(1, 14):
            b = _shift_rows(b.translate(SBOX_B))
            b = (int.from_bytes(_mix_columns(b), "big") ^ rk[rnd]).to_bytes(16, "big")
        b = _shift_rows(b.translate(SBOX_B))
        return int.from_bytes(b, "big") ^ rk[14]

    def decrypt_int(self, s):
        rk = self.rk
        b = (s ^ rk[14]).to_bytes(16, "big")
        for rnd in range(13, 0, -1):
            b = int.from_bytes(_inv_shift_rows(b).translate(INV_SBOX_B), "big").to_bytes(16, "big")
            b = (int.from_bytes(b, "big") ^ rk[rnd]).to_bytes(16, "big")
            b = _inv_mix_columns(b)
        b = _inv_shift_rows(b).translate(INV_SBOX_B)
        return int.from_bytes(b, "big") ^ rk[0]

    def encrypt_block(self, blk):
        return self.encrypt_int(int.from_bytes(blk, "big")).to_bytes(16, "big")

    def decrypt_block(self, blk):
        return self.decrypt_int(int.from_bytes(blk, "big")).to_bytes(16, "big")


@functools.lru_cache(maxsize=16)
def _aes(key):
    return AES(key)


def aes_cbc_decrypt(key, iv, ct):
    aes = _aes(bytes(key))
    n = len(ct) // 16
    if not n:
        return b""
    dec = aes.decrypt_int
    out = bytearray(n * 16)
    prev = int.from_bytes(iv, "big")
    for i in range(n):
        off = i * 16
        blk = int.from_bytes(ct[off:off + 16], "big")
        out[off:off + 16] = (dec(blk) ^ prev).to_bytes(16, "big")
        prev = blk
    pad = out[-1]
    if 1 <= pad <= 16 and out[-pad:] == bytes([pad]) * pad:
        del out[-pad:]
    return bytes(out)


def aes_cbc_encrypt(key, iv, pt, pad=True):
    """PKCS#7 填充后加密（自测 / 构造回放样本用；线上链路只需解密）"""
    aes = _aes(bytes(key))
    if pad:
        n = 16 - (len(pt) % 16)
        pt = pt + bytes([n]) * n
    out = bytearray(len(pt))
    prev = int.from_bytes(iv, "big")
    for i in range(0, len(pt), 16):
        prev = aes.encrypt_int(int.from_bytes(pt[i:i + 16], "big") ^ prev)
        out[i:i + 16] = prev.to_bytes(16, "big")
    return bytes(out)


def _gcm_ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        blk = data[i:i + 16].ljust(16, b"\x00")
        y ^= int.from_bytes(blk, "big")
        z = 0
        v = y
        for bit in range(128):
            if (h >> (127 - bit)) & 1:
                z ^= v
            lsb = v & 1
            v >>= 1
            if lsb:
                v ^= 0xE1000000000000000000000000000000
        y = z
    return y.to_bytes(16, "big")


def _inc32(b):
    return b[:12] + ((int.from_bytes(b[12:], "big") + 1) & 0xFFFFFFFF).to_bytes(4, "big")


def aes_gcm_encrypt(key, iv, plaintext, aad=b""):
    """返回 ciphertext || 16 字节 tag（与 WebCrypto encrypt + getAuthTag 拼接等价）"""
    aes = _aes(bytes(key))
    h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
    j0 = iv + b"\x00\x00\x00\x01"
    ctr = _inc32(j0)
    ks, counter = bytearray(), ctr
    while len(ks) < len(plaintext):
        ks += aes.encrypt_block(counter)
        counter = _inc32(counter)
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    la = (len(aad) * 8).to_bytes(8, "big")
    lc = (len(ct) * 8).to_bytes(8, "big")
    pad = b"\x00" * ((16 - (len(aad) % 16)) % 16)
    padc = b"\x00" * ((16 - (len(ct) % 16)) % 16)
    s = _gcm_ghash(h, aad + pad + ct + padc + la + lc)
    tag = bytes(a ^ b for a, b in zip(aes.encrypt_block(j0), s))
    return ct + tag


# ======================================================================
# 2. 响应混淆链还原
# ======================================================================
# XOR90 / 每 8 字符反转 / 自定义字母表，三步都是定长变换 —— 预建 256 项表，运行期 C 速度 translate。
_T_XOR90 = bytes(b ^ 90 for b in range(256))
_ALPHA_MAP = {ch: STD_ALPHABET[i] for i, ch in enumerate(CUSTOM_ALPHABET)}
_T_ALPHA = bytes(ord(_ALPHA_MAP.get(chr(b), chr(b))) for b in range(256))


def _as_bytes(s):
    return s.encode("latin-1") if isinstance(s, str) else s


def _xor90(s):
    return _as_bytes(s).translate(_T_XOR90)


def _rev8(s, n=8):
    s = _as_bytes(s)
    if len(s) <= n:
        return s[::-1]
    return b"".join(s[i:i + n][::-1] for i in range(0, len(s), n))


def _unshuffle(s):
    return _as_bytes(s).translate(_T_ALPHA)


def _b64(s):
    s = _as_bytes(s).strip()
    return base64.b64decode(s + b"=" * (-len(s) % 4))


def generate_output(data_b64, key_b64, salt=SALT):
    """/api/parse 响应：先 base64 解码 -> XOR90 -> 每 8 字符块反转 -> 字母表还原 (chunk 2261)"""
    ct = _b64(_unshuffle(_rev8(_xor90(base64.b64decode(data_b64)))))
    iv = _b64(_unshuffle(_rev8(_xor90(base64.b64decode(key_b64)))))
    return json.loads(aes_cbc_decrypt(salt, iv, ct).decode("utf-8"))


def decrypt_more_size_response(data, iv, token):
    """/api/more-size 响应：直接对字符串 XOR90 -> 反转 -> 还原；key=SHA256(token) (chunk 951)"""
    key = hashlib.sha256(token.encode()).digest()
    ct = _b64(_unshuffle(_rev8(_xor90(data))))
    ivb = _b64(_unshuffle(_rev8(_xor90(iv))))
    return json.loads(aes_cbc_decrypt(key, ivb, ct).decode("utf-8"))


# ======================================================================
# 3. 会话与协议
# ======================================================================
class Session:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPRedirectHandler(),
        )
        self.referer = BASE + DEFAULT_PAGE_PATH
        self.timeout = 40

    def request(self, url, method="GET", body=None, headers=None, retries=2):
        """单次请求；瞬时失败（超时 / 连接重置 / 429 / 5xx）指数退避重试。
        返回 (status, body)；彻底失败给 (0, b"")，让上层走同一条失败分支。"""
        data = json.dumps(body).encode() if body is not None else None
        delay = 0.6
        for attempt in range(retries + 1):
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("accept", "*/*")
            req.add_header("accept-language", "zh-CN,zh;q=0.9")
            req.add_header("origin", BASE)
            req.add_header("referer", self.referer)
            req.add_header("user-agent", UA)
            if data is not None:
                req.add_header("content-type", "application/json")
            for k, v in (headers or {}).items():
                req.add_header(k, v)
            try:
                with self.opener.open(req, timeout=self.timeout) as r:
                    return r.status, r.read()
            except urllib.error.HTTPError as e:
                payload = e.read()
                if e.code not in (429, 500, 502, 503, 504) or attempt >= retries:
                    return e.code, payload
            except Exception:
                if attempt >= retries:
                    return 0, b""
            time.sleep(delay)
            delay = min(delay * 2, 8.0)
        return 0, b""

    def sid(self):
        for c in self.jar:
            if c.name == "parse_sid":
                return c.value
        return None


def _json(b):
    try:
        return json.loads(b.decode("utf-8"))
    except Exception:
        return {"raw": b[:400].decode("utf-8", "ignore")}


def gate(sess, request_url, route="gate-e5eea8"):
    """取解析票据，同时建立 parse_sid 匿名会话（more-size 的 subject 绑定它）"""
    st, b = sess.request(f"{BASE}/api/{route}", "POST",
                         {"requestURL": request_url, "isBatch": False, "mode": "single"})
    return st, _json(b), sess.sid()


def parse(sess, request_url, uwx_id=None, page_path=DEFAULT_PAGE_PATH, quality_tier="hd",
          is_mobile=False, route="gate-e5eea8"):
    sess.referer = BASE + page_path          # 平台由 Referer 决定
    st, g, sid = gate(sess, request_url, route)
    ticket, seed = None, None
    fields = ("tk_e5eea8", "pl_e5eea8", "iv_e5eea8", "vr_e5eea8")
    if g.get("tk_e5eea8"):
        ticket, seed = g["tk_e5eea8"], g["sd_e5eea8"]
    elif g.get("tk_4a160a"):
        fields = ("tk_4a160a", "pl_4a160a", "iv_4a160a", "vr_4a160a")
        ticket, seed = g["tk_4a160a"], g["sd_4a160a"]
    if not ticket:
        return {"ok": False, "stage": "gate", "httpStatus": st, "gate": g}
    key = hashlib.sha256(f"{ticket}:{seed}".encode()).digest()
    iv = os.urandom(12)
    plain = {
        "requestURL": request_url, "isBatch": False, "parseMode": "single",
        "isMobile": "true" if is_mobile else "false", "isoCode": "CN",
        "adType": "adsense", "uwx_id": uwx_id, "pagePath": page_path,
        "externalRequestId": str(uuid.uuid4()), "qualityTier": quality_tier,
    }
    ct = aes_gcm_encrypt(key, iv, json.dumps(plain, separators=(",", ":")).encode())
    body = {fields[0]: ticket, fields[1]: base64.b64encode(ct).decode(),
            fields[2]: base64.b64encode(iv).decode(), fields[3]: 1}
    st, b = sess.request(f"{BASE}/api/parse", "POST", body)
    raw = _json(b)
    if not raw.get("encrypt"):
        return {"ok": False, "stage": "parse", "httpStatus": st, "raw": raw}
    try:
        payload = generate_output(raw["data"], raw["key"])
    except Exception as e:                      # 解密链路异常不吞掉，交给上层展示
        return {"ok": False, "stage": "decrypt", "httpStatus": st, "raw": raw,
                "error": "%s: %s" % (type(e).__name__, e)}
    return {"ok": True, "httpStatus": st, "qualityTier": raw.get("qualityTier"),
            "payload": payload, "raw": raw}


def more_size(sess, input_str, token):
    st, b = sess.request(f"{BASE}/api/more-size", "POST", {"input": input_str},
                         headers={"X-More-Size-Token": token})
    raw = _json(b)
    if not raw.get("encrypt"):
        return {"ok": False, "httpStatus": st, "raw": raw}
    return {"ok": True, "httpStatus": st,
            "data": decrypt_more_size_response(raw["data"], raw["iv"], token)}


def proxy_url(sess, src, kind="video"):
    st, b = sess.request(f"{BASE}/api/download-proxy-url", "POST",
                         {"url": src, "sourceUrl": src, "type": kind})
    j = _json(b)
    return {"status": st, "url": j.get("url"), "raw": j}


def proxy_url_stateless(src, referer, kind="video", timeout=45):
    """无 cookie 依赖的换链，可安全并发（WebUI 的探针/下载/压缩都用它）"""
    body = json.dumps({"url": src, "sourceUrl": src, "type": kind}).encode()
    req = urllib.request.Request(BASE + "/api/download-proxy-url", data=body, method="POST")
    req.add_header("content-type", "application/json")
    req.add_header("origin", BASE)
    req.add_header("referer", referer)
    req.add_header("user-agent", UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode()).get("url")
    except Exception:
        return None


def uwx_id(sess):
    st, b = sess.request(f"{BASE}/account/api/uwx/generate-id", "POST", {})
    j = _json(b)
    if j.get("success") and j.get("data", {}).get("uwx_id"):
        return j["data"]["uwx_id"]
    return "uwx_%s%sAA" % (str(int(time.time() * 1000))[-6:],
                           uuid.uuid4().hex[:4])


def fetch_head(url, referer, range_hdr=None, timeout=120, max_bytes=None):
    """取 URL 内容；给了 range_hdr 就只取该区间，max_bytes 用来兜住异常大的响应。"""
    req = urllib.request.Request(url)
    req.add_header("user-agent", UA)
    req.add_header("referer", referer)
    req.add_header("accept", "*/*")
    if range_hdr:
        req.add_header("range", range_hdr)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        buf = r.read(max_bytes) if max_bytes else r.read()
        st = r.status
    return st, buf


def total_size(headers):
    """从 content-range 的「/总数」或 content-length 拿文件体积（headers 用小写键）"""
    cr = headers.get("content-range") or ""
    if "/" in cr:
        t = cr.rsplit("/", 1)[1].strip()
        if t.isdigit():
            return int(t)
    cl = str(headers.get("content-length") or "").strip()
    return int(cl) if cl.isdigit() else 0


def probe(url, referer, rng=None, timeout=45):
    """一次请求同时拿到状态码 / 真实体积 / 片段字节（片段里有 moov 就能算分辨率）。
    返回 {status, headers, body, size, dim}；网络异常时 status=0 并带 error。"""
    req = urllib.request.Request(url)
    req.add_header("user-agent", UA)
    req.add_header("referer", referer)
    req.add_header("accept", "*/*")
    if rng:
        req.add_header("range", rng)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            st, body = r.status, r.read()
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        st, body = e.code, e.read()
    except Exception as e:
        return {"status": 0, "headers": {}, "body": b"", "size": 0, "dim": None,
                "error": "%s: %s" % (type(e).__name__, e)}
    return {"status": st, "headers": hdrs, "body": body, "size": total_size(hdrs),
            "dim": tkhd_dim(body) if body else None}


def measure(src_proxy, referer, timeout=45):
    """量一档：头 64KB 一次拿状态/总体积/分辨率；头里没有 moov 再补一次尾部 256KB。
    相比「HEAD + 两次 GET」少一半请求（实测每档 3~4 个请求降到 1~2 个）。"""
    r = probe(src_proxy, referer, "bytes=0-65535", timeout=timeout)
    if r["status"] not in (200, 206):
        return r
    if not r["dim"]:
        tail = probe(src_proxy, referer, "bytes=-262144", timeout=timeout)
        r["dim"] = tail["dim"]
        r["size"] = r["size"] or tail["size"]
    if r["size"] and r["status"] == 200 and r["size"] > len(r["body"]) * 4:
        # 服务端忽略 Range 回了整文件时，content-length 就是总量
        r["size"] = r["size"]
    return r


def download(url, referer, path, total=0, timeout=180, chunk=262144, retries=3):
    """流式下载到 path：已存在就按 Range 断点续传，服务端不支持 Range 则整文件重下。
    返回 (落地字节数, 是否完整)。"""
    for attempt in range(retries + 1):
        have = os.path.getsize(path) if os.path.exists(path) else 0
        if total and have >= total:
            return have, True
        req = urllib.request.Request(url)
        req.add_header("user-agent", UA)
        req.add_header("referer", referer)
        req.add_header("accept", "*/*")
        if have and total:
            req.add_header("range", "bytes=%d-" % have)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if have and r.status == 200:      # 忽略 Range 的服务器只能重下
                    have = 0
                with open(path, "ab" if have else "wb") as f:
                    while True:
                        block = r.read(chunk)
                        if not block:
                            break
                        f.write(block)
        except Exception:
            if attempt >= retries:
                break
            time.sleep(0.8 * (attempt + 1))
            continue
        got = os.path.getsize(path) if os.path.exists(path) else 0
        if not total or got >= total:
            return got, True
        if got <= have:                            # 本轮零进展，别空转
            break
    got = os.path.getsize(path) if os.path.exists(path) else 0
    return got, bool(total) and got >= total


def tkhd_dim(buf):
    """遍历全部 tkhd box，取宽高非零的那一条（音轨 tkhd 的宽高为 0）。
    tkhd 载荷布局：version+flags(4) | v0:20 / v1:32 | reserved(8) | layer+alt+vol+resv(8) | matrix(36)
    盒体为 [4B size][4B 'tkhd'][载荷]，故载荷起点 = 类型串位置 +4
    -> v0 宽 @i+80、高 @i+84；v1 宽 @i+92、高 @i+96（16.16 定点）"""
    off = 0
    while True:
        i = buf.find(b"tkhd", off)
        if i < 0:
            return None
        off = i + 4
        if i < 4 or len(buf) < i + 100:
            continue
        ver = buf[i + 4]
        # 类型串位置 i +4(盒头) +4(ver/flags) +12/24(时间字段) +8(reserved)
        #   +8(layer/alt/vol) +36(matrix) -> v0: i+80、v1: i+92
        base = i + (92 if ver == 1 else 80)
        w = int.from_bytes(buf[base:base + 4], "big") / 65536
        h = int.from_bytes(buf[base + 4:base + 8], "big") / 65536
        if w and h:
            return "%dx%d" % (w, h)


# ======================================================================
# 4. 共用小工具（CLI 与 WebUI 共用，避免两处各写一份）
# ======================================================================
_URL_RX = re.compile(r"https?://[^\s\"'<>]+", re.I)
_CN_RX = re.compile(r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]+")


def extract_url(text):
    """从分享文案里取出链接（抖音/小红书/快手 App 分享出来的都是一段话 + 链接）。"""
    if not text:
        return ""
    text = text.strip()
    m = _URL_RX.search(text)
    if not m:
        return ""
    url = m.group(0).rstrip("，。,.、）)】]》>\"'")
    return html.unescape(url)                 # 网页里粘出来的链接常带 &amp;


def canonical_url(text):
    """用于缓存键：取出链接并去掉追踪参数以外的差异（保留 query，签名可能在其中）。"""
    return extract_url(text) or (text or "").strip()


def detect_platform(url):
    for name, path, pat in PLATFORMS:
        if re.search(pat, url or "", re.I):
            return name, path
    return "douyin", DEFAULT_PAGE_PATH


def br_of(url):
    """CDN 直链 query 里的 br= 码率（kbps），拿不到返回 0"""
    try:
        return int(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("br", ["0"])[0])
    except Exception:
        return 0


def quality_label(src, known_type=None):
    if known_type:
        return known_type
    br = br_of(src)
    return ("%skbps" % br) if br else "原始档"


def dedupe_by_size(cands, size_key="size"):
    """同体积视为同一文件：按体积降序，重复体积只留第一条（保持顺序）。"""
    seen, out = set(), []
    for c in sorted(cands or [], key=lambda x: -(x.get(size_key) or 0)):
        s = c.get(size_key) or 0
        if s and s in seen:
            continue
        if s:
            seen.add(s)
        out.append(c)
    return out


def pick_best(cands):
    """第一条真正可下的档位下标（HTTP 200/206 且体积 > 1 KiB）"""
    for i, c in enumerate(cands or []):
        if c.get("status") in (200, 206) and (c.get("size") or 0) > 1024:
            return i
    return None


def pool_from_payload(payload):
    """parse 回执 -> {url: {label,sizeHint,source}}（不含 more-size 的追加）"""
    pool = {}
    info = (payload.get("videos") or [{}])[0]
    for v in info.get("video_fullinfo", []) or []:
        if v.get("url"):
            pool[v["url"]] = {"label": v.get("type"),
                              "sizeHint": int(v.get("size") or 0), "source": "parse"}
    if info.get("url"):
        pool.setdefault(info["url"], {"label": None, "sizeHint": 0, "source": "parse"})
    return pool


# ======================================================================
# 5. CLI
# ======================================================================
def _human(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


# ======================================================================
# 5. X（推特）：yt-dlp 兜底
# ======================================================================
HERE = os.path.dirname(os.path.abspath(__file__))
YTDLP_HINT = ("未找到 yt-dlp：pip install -U yt-dlp 装一个，或用 YTDLP=/path/to/yt-dlp 指定；"
              "直连 X 需要代理，例如 X_PROXY=http://127.0.0.1:7890")


def ytdlp_bin():
    """按 YTDLP 环境变量 → PATH → 仓库 bin/ 的顺序找 yt-dlp 可执行文件"""
    env = os.environ.get("YTDLP") or os.environ.get("YT_DLP")
    if env:
        return env if os.path.exists(env) else shutil.which(env)
    found = shutil.which("yt-dlp")
    if found:
        return found
    for name in ("yt-dlp.exe", "yt-dlp"):
        p = os.path.join(HERE, "bin", name)
        if os.path.exists(p):
            return p
    return None


def x_proxy():
    """yt-dlp 出网用的代理：优先 X_PROXY，其次常见的 HTTPS_PROXY / ALL_PROXY"""
    return (os.environ.get("X_PROXY") or os.environ.get("HTTPS_PROXY")
            or os.environ.get("ALL_PROXY") or "")


def _run_ytdlp(url, timeout=90):
    """跑 `yt-dlp -J`，返回 (info dict, 错误串)；只解析不下载"""
    exe = ytdlp_bin()
    if not exe:
        return None, YTDLP_HINT
    cmd = [exe, "-J", "--no-warnings", "--no-playlist", url]
    px = x_proxy()
    if px:
        cmd[1:1] = ["--proxy", px]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "yt-dlp 超时（%ss）%s" % (timeout, "，代理未生效？" if not px else "")
    except OSError as e:
        return None, "yt-dlp 启动失败：%s" % e
    if r.returncode != 0:
        lines = (r.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        msg = lines[-1] if lines else "yt-dlp 退出码 %d" % r.returncode
        return None, msg[:300]
    try:
        return json.loads((r.stdout or b"{}").decode("utf-8", "replace")), ""
    except ValueError:
        return None, "yt-dlp 输出不是 JSON"


def x_formats_to_cands(info):
    """yt-dlp 的 info dict → 档位列表。
    去掉纯音轨与 m3u8（同码率重复），按 (height, tbr) 去重，再按分辨率/码率降序；
    DASH 分片常没有 filesize，用 tbr×时长估算一个体积，好让 pick_best 有依据。"""
    dur = float((info or {}).get("duration") or 0)
    out, seen = [], set()
    for f in (info or {}).get("formats") or []:
        src = f.get("url") or ""
        if not src or (f.get("vcodec") or "none") == "none":
            continue
        if f.get("ext") in ("mhtml", "none") or str(f.get("protocol") or "").startswith("m3u8"):
            continue
        h = int(f.get("height") or 0)
        w = int(f.get("width") or 0)
        tbr = float(f.get("tbr") or f.get("vbr") or 0)
        key = (h, int(tbr))
        if h and key in seen:
            continue
        if h:
            seen.add(key)
        size = int(f.get("filesize") or f.get("filesize_approx") or 0)
        if not size and tbr and dur:
            size = int(tbr * 1000 / 8 * dur)
        out.append({"src": src, "label": ("%dp" % h) if h else "原始档", "size": size,
                    "dim": ("%dx%d" % (w, h)) if w and h else None, "br": int(tbr),
                    "source": "ytdlp", "proxy": src, "status": 200,
                    "ext": f.get("ext") or "mp4", "_h": h})
    out.sort(key=lambda c: (-c["_h"], -c["br"], -c["size"]))
    for c in out:
        c.pop("_h", None)
    return out


def x_from_ytdlp(url, timeout=90):
    """单条推文 → {ok,title,author,cover,candidates,best,source,error}
    依赖本机 yt-dlp 能出网（境内需代理）；只拿直链，不落盘。"""
    info, err = _run_ytdlp(url, timeout=timeout)
    if not info:
        return {"ok": False, "source": "ytdlp", "candidates": [], "error": err}
    cands = x_formats_to_cands(info)
    if not cands:
        return {"ok": False, "source": "ytdlp", "candidates": [],
                "error": "yt-dlp 没解析出视频流（可能受保护或需要登录）"}
    best = pick_best(cands)
    if best is None:
        best = 0
    return {"ok": True, "source": "ytdlp", "title": info.get("title") or "",
            "author": info.get("uploader") or info.get("channel") or "",
            "cover": info.get("thumbnail") or "", "duration": info.get("duration"),
            "candidates": cands, "best": best,
            "webpage_url": info.get("webpage_url") or url}


def _main_x(a, share):
    """CLI 的 X 分支：yt-dlp 解析 → 打印档位 → 可选下载"""
    t0 = time.time()
    r = x_from_ytdlp(share, timeout=max(60, int(a.timeout * 3)))
    if not r.get("ok"):
        msg = r.get("error") or "未知错误"
        print("FAILED: " + msg, file=sys.stderr)
        if a.json:
            print(json.dumps({"ok": False, "platform": "x", "error": msg}, ensure_ascii=False))
        return 1
    cands, best = r["candidates"], r.get("best") or 0
    if a.quality:
        want = a.quality.strip().lower()
        for i, c in enumerate(cands):
            hay = " ".join(str(x or "").lower()
                           for x in (c.get("label"), c.get("dim"), c.get("br")))
            if want in hay:
                best = i
                break
    out = {"input": share, "platform": "x", "engine": "yt-dlp", "title": r.get("title"),
           "author": r.get("author"), "type": "video", "cover": r.get("cover"),
           "candidates": cands, "best": best,
           "timing": {"parse": round(time.time() - t0, 2)}}
    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print("平台 x   引擎 yt-dlp   解析 %.2fs" % (time.time() - t0))
        print("标题 %s%s" % (r.get("title") or "（无）",
                            ("  @" + r["author"]) if r.get("author") else ""))
        print("档位:")
        for i, c in enumerate(cands):
            print("  %d. %-10s %10s  %-11s %6s  [%s]%s"
                  % (i + 1, c.get("label") or "-", _human(c.get("size")),
                     c.get("dim") or "-", ("%dkbps" % c["br"]) if c.get("br") else "-",
                     c["source"], "  <= 最佳" if i == best else ""))
    if a.download and cands:
        c = cands[best]
        os.makedirs(a.out, exist_ok=True)
        safe = re.sub(r'[\\/:*?"<>|\s]+', "_", str(r.get("title") or "x_video"))[:60]
        tag = c.get("dim") or (("%dkbps" % c["br"]) if c.get("br") else "best")
        fp = os.path.join(a.out, "%s_%s.%s" % (safe, tag, c.get("ext") or "mp4"))
        t1 = time.time()
        got, done = download(c["src"], "https://x.com/", fp, total=c.get("size") or 0,
                             timeout=max(180, a.timeout))
        if not a.json:
            print("已保存 %s  (%s, %.1fs%s)"
                  % (fp, _human(got), time.time() - t1, "" if done else ", 未下完可重跑续传"))
        out["download"] = {"path": fp, "bytes": got, "complete": done}
    return 0


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(
        prog="hellotik_dl.py", add_help=True,
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("link", nargs="*", help="分享链接或 App 分享文案")
    ap.add_argument("-m", "--more-size", action="store_true", help="追取更高码率（more-size）")
    ap.add_argument("-d", "--download", action="store_true", help="下载最高档")
    ap.add_argument("--out", default="dl", help="下载目录（默认 dl/）")
    ap.add_argument("--quality", default=None, help="指定档位标签，如 720p / 原始档")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    ap.add_argument("--dump-parse", action="store_true", help="打印解密后的原始 payload")
    ap.add_argument("--no-measure", action="store_true", help="不逐档探测真实体积/分辨率")
    ap.add_argument("--timeout", type=float, default=40, help="单请求超时秒数（默认 40）")
    ap.add_argument("--concurrency", type=int, default=6, help="并发探测数（默认 6）")
    a = ap.parse_args(argv)

    share = extract_url(" ".join(a.link)) if a.link else ""
    if not share:
        ap.print_help()
        return 2
    platform, page_path = detect_platform(share)
    if platform == "x":                          # 站方不支持 X：走本机 yt-dlp（需能出网）
        return _main_x(a, share)

    sess = Session()
    sess.timeout = a.timeout
    t0 = time.time()
    dev = uwx_id(sess)
    r = parse(sess, share, uwx_id=dev, page_path=page_path)
    if not r.get("ok"):
        print("FAILED: " + json.dumps(r, ensure_ascii=False)[:800], file=sys.stderr)
        return 1
    p = r["payload"]
    t_parse = time.time() - t0

    out = {
        "input": share, "platform": platform, "page_path": page_path,
        "qualityTier": r.get("qualityTier"), "title": p.get("title"), "type": p.get("type"),
        "source_url": p.get("url"), "cover": p.get("cover"),
        "moreSizeToken": bool(p.get("moreSizeToken")),
        "timing": {"parse": round(t_parse, 2)},
    }

    pool = pool_from_payload(p)
    if a.more_size and p.get("moreSizeToken"):
        t1 = time.time()
        ms = more_size(sess, share, p["moreSizeToken"])
        if ms.get("ok"):
            d = ms["data"]
            if d.get("url"):
                pool[d["url"]] = {"label": "原始档", "sizeHint": 0, "source": "more-size"}
            for v in d.get("variants", []) or []:
                if v.get("url"):
                    pool.setdefault(v["url"], {"label": None, "sizeHint": 0,
                                               "source": "more-size"})
            out["more_size_variants"] = len(pool)
            out["timing"]["more_size"] = round(time.time() - t1, 2)
        else:
            out["more_size_error"] = (ms.get("raw") or {}).get("error") or ms.get("httpStatus")

    cands = [{"src": u, "label": c["label"] or quality_label(u), "size": c["sizeHint"],
              "dim": None, "br": br_of(u), "source": c["source"], "proxy": None, "status": 0}
             for u, c in pool.items()]

    if not a.no_measure and cands:
        t2 = time.time()
        from concurrent.futures import ThreadPoolExecutor

        def _one(c):
            px = proxy_url_stateless(c["src"], sess.referer)
            if not px:
                return c
            c["proxy"] = px
            m = measure(px, sess.referer, timeout=a.timeout)
            c["status"] = m["status"]
            c["size"] = m["size"] or c["sizeHint"]
            c["dim"] = m["dim"]
            if m.get("error"):
                c["error"] = m["error"]
            return c

        with ThreadPoolExecutor(max_workers=max(1, a.concurrency)) as ex:
            cands = list(ex.map(_one, cands))
        out["timing"]["probe"] = round(time.time() - t2, 2)

    cands = dedupe_by_size(cands)
    best = pick_best(cands)
    if best is None and cands:
        best = 0                                 # 全都没探测成功时退回第一档
    if a.quality:
        want = a.quality.strip().lower()

        def _hit(c):
            hay = " ".join(str(x or "").lower() for x in
                           (c.get("label"), c.get("dim"), c.get("br")))
            return want in hay
        for i, c in enumerate(cands):
            if _hit(c):
                best = i
                break
    out["candidates"] = cands
    out["best"] = best

    if a.dump_parse:
        out["parse_payload"] = p

    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print("平台 %s   类型 %s   qualityTier %s   解析 %.2fs"
              % (platform, p.get("type"), r.get("qualityTier"), t_parse))
        print("标题 %s" % (p.get("title") or "（无）"))
        print("档位:")
        for i, c in enumerate(cands):
            mark = "  <= 最佳" if i == best else ""
            print("  %d. %-10s %10s  %-11s %6s  [%s]%s"
                  % (i + 1, c.get("label") or "-", _human(c.get("size")),
                     c.get("dim") or "-", ("%skbps" % c["br"]) if c.get("br") else "-",
                     c.get("source"), mark))
        if out.get("more_size_error"):
            print("more-size 未成功: %s" % out["more_size_error"])

    if a.download and best is not None and 0 <= best < len(cands):
        c = cands[best]
        px = c.get("proxy") or proxy_url_stateless(c["src"], sess.referer)
        if not px:
            print("换链失败，无法下载", file=sys.stderr)
            return 1
        os.makedirs(a.out, exist_ok=True)
        safe = re.sub(r'[\\/:*?"<>|\s]+', "_", str(p.get("title") or "media"))[:60]
        tag = c.get("dim") or ("%skbps" % c["br"] if c.get("br") else "best")
        fp = os.path.join(a.out, "%s_%s.mp4" % (safe, tag))
        t3 = time.time()
        got, done = download(px, sess.referer, fp, total=c.get("size") or 0,
                             timeout=max(180, a.timeout))
        if not a.json:
            print("已保存 %s  (%s, %.1fs%s)"
                  % (fp, _human(got), time.time() - t3, "" if done else ", 未下完可重跑续传"))
        out["download"] = {"path": fp, "bytes": got, "complete": done}
    return 0


if __name__ == "__main__":
    sys.exit(main())
