#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hellotik.app 抖音 / 小红书 无水印解析下载 —— 纯标准库 Python 复现（研究用）

逆向自站点 JS chunk（全部为静态分析所得）：
  chunk 2716 / module 62261 : generateOutput(data, key, salt)         解析响应解密
  chunk 951  / module 60951 : decryptMoreSizeResponse(data, iv, token) 更高码率响应解密
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

用法:
  python hellotik_dl.py <分享链接> [--more-size] [--download] [--json] [--dump-parse]
"""
import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar
import uuid

BASE = "https://www.hellotik.app"
SALT = b"93838338562359368888868323563256"  # chunk 2261 硬编码（32 字节 = AES-256 密钥）
CUSTOM_ALPHABET = "ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw9876543210-_"
STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


# ======================================================================
# 1. 纯 Python AES-256 / AES-CBC / AES-GCM
# ======================================================================
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
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


class AES:
    """仅 AES-256（Nk=8, Nr=14）"""

    def __init__(self, key):
        assert len(key) == 32, "AES-256 requires a 32-byte key"
        self.w = self._expand(key)

    @staticmethod
    def _expand(key):
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

    @staticmethod
    def _add_round_key(s, w, rnd):
        for c in range(4):
            for r in range(4):
                s[r][c] ^= w[rnd * 4 + c][r]

    @staticmethod
    def _shift_rows(s):
        for r in range(1, 4):
            s[r] = s[r][r:] + s[r][:r]

    @staticmethod
    def _inv_shift_rows(s):
        for r in range(1, 4):
            s[r] = s[r][-r:] + s[r][:-r]

    @staticmethod
    def _mix_columns(s):
        for c in range(4):
            a = [s[r][c] for r in range(4)]
            s[0][c] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
            s[1][c] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
            s[2][c] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
            s[3][c] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)

    @staticmethod
    def _inv_mix_columns(s):
        for c in range(4):
            a = [s[r][c] for r in range(4)]
            s[0][c] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
            s[1][c] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
            s[2][c] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
            s[3][c] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)

    def encrypt_block(self, blk):
        s = [[blk[r + 4 * c] for c in range(4)] for r in range(4)]
        self._add_round_key(s, self.w, 0)
        for rnd in range(1, 14):
            s = [[SBOX[b] for b in row] for row in s]
            self._shift_rows(s)
            self._mix_columns(s)
            self._add_round_key(s, self.w, rnd)
        s = [[SBOX[b] for b in row] for row in s]
        self._shift_rows(s)
        self._add_round_key(s, self.w, 14)
        return bytes(s[r][c] for c in range(4) for r in range(4))

    def decrypt_block(self, blk):
        s = [[blk[r + 4 * c] for c in range(4)] for r in range(4)]
        self._add_round_key(s, self.w, 14)
        for rnd in range(13, 0, -1):
            self._inv_shift_rows(s)
            s = [[INV_SBOX[b] for b in row] for row in s]
            self._add_round_key(s, self.w, rnd)
            self._inv_mix_columns(s)
        self._inv_shift_rows(s)
        s = [[INV_SBOX[b] for b in row] for row in s]
        self._add_round_key(s, self.w, 0)
        return bytes(s[r][c] for c in range(4) for r in range(4))


def aes_cbc_decrypt(key, iv, ct):
    aes = AES(key)
    out = b""
    prev = iv
    for i in range(0, len(ct), 16):
        blk = ct[i:i + 16]
        dec = aes.decrypt_block(blk)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    if not out:
        return out
    pad = out[-1]
    if 1 <= pad <= 16 and out.endswith(bytes([pad]) * pad):
        out = out[:-pad]
    return out


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
    aes = AES(key)
    h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
    j0 = iv + b"\x00\x00\x00\x01"
    ctr = _inc32(j0)
    ks, counter = b"", ctr
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
def _xor90(s):
    return "".join(chr(ord(c) ^ 90) for c in s)


def _rev8(s, n=8):
    return "".join(s[i:i + n][::-1] for i in range(0, len(s), n))


def _unshuffle(s):
    return "".join(STD_ALPHABET[CUSTOM_ALPHABET.index(c)] if c in CUSTOM_ALPHABET else c for c in s)


def _b64(s):
    s = s.strip()
    return base64.b64decode(s + "=" * (-len(s) % 4))


def generate_output(data_b64, key_b64, salt=SALT):
    """/api/parse 响应：先 base64 解码 -> XOR90 -> 每 8 字符块反转 -> 字母表还原 (chunk 2261)"""
    ct = _b64(_unshuffle(_rev8(_xor90(base64.b64decode(data_b64).decode("latin-1")))))
    iv = _b64(_unshuffle(_rev8(_xor90(base64.b64decode(key_b64).decode("latin-1")))))
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
        self.referer = BASE + "/zh/douyin"

    def request(self, url, method="GET", body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
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
            with self.opener.open(req, timeout=40) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

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


def parse(sess, request_url, uwx_id=None, page_path="/zh/douyin", quality_tier="hd",
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


def uwx_id(sess):
    st, b = sess.request(f"{BASE}/account/api/uwx/generate-id", "POST", {})
    j = _json(b)
    if j.get("success") and j.get("data", {}).get("uwx_id"):
        return j["data"]["uwx_id"]
    return "uwx_%s%sAA" % (str(int(time.time() * 1000))[-6:],
                           uuid.uuid4().hex[:4])


def fetch_head(url, referer):
    req = urllib.request.Request(url, headers={"user-agent": UA, "referer": referer})
    with urllib.request.urlopen(req, timeout=120) as r:
        buf = r.read()
    return r.status, buf


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
        base = i + (92 if ver == 1 else 80)
        w = int.from_bytes(buf[base:base + 4], "big") / 65536
        h = int.from_bytes(buf[base + 4:base + 8], "big") / 65536
        if w and h:
            return "%dx%d" % (w, h)


# ======================================================================
# 4. CLI
# ======================================================================
def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    args = [a for a in sys.argv[1:]]
    if not args or args[0].startswith("-"):
        print(__doc__)
        return 2
    share = args[0]
    want_more = "--more-size" in args
    want_dl = "--download" in args
    platform = "rednote" if re.search(r"xiaohongshu|xhslink", share, re.I) else "douyin"
    page_path = "/zh/rednote" if platform == "rednote" else "/zh/douyin"

    sess = Session()
    dev = uwx_id(sess)
    r = parse(sess, share, uwx_id=dev, page_path=page_path)
    if not r.get("ok"):
        print("FAILED: " + json.dumps(r, ensure_ascii=False)[:800])
        return 1
    p = r["payload"]
    out = {
        "input": share, "platform": platform, "page_path": page_path,
        "qualityTier": r.get("qualityTier"), "title": p.get("title"), "type": p.get("type"),
        "source_url": p.get("url"), "cover": p.get("cover"),
        "tiers": ["%s(%sB)" % (v.get("type"), v.get("size"))
                  for v in (p.get("videos") or [{}])[0].get("video_fullinfo", [])],
        "moreSizeToken": bool(p.get("moreSizeToken")),
    }

    def br(u):
        try:
            return int(urllib.parse.parse_qs(urllib.parse.urlparse(u).query).get("br", ["0"])[0])
        except Exception:
            return 0

    pool = {}
    for v in (p.get("videos") or [{}])[0].get("video_fullinfo", []):
        if v.get("url"):
            pool[v["url"]] = {"url": v["url"], "label": v.get("type"), "known": v.get("size")}
    if (p.get("videos") or [{}])[0].get("url"):
        pool[p["videos"][0]["url"]] = {"url": p["videos"][0]["url"]}

    if want_more and p.get("moreSizeToken"):
        ms = more_size(sess, share, p["moreSizeToken"])
        if ms.get("ok"):
            cand = [ms["data"].get("url")] + [v.get("url") for v in ms["data"].get("variants", [])]
            for u in cand:
                if u:
                    pool[u] = {"url": u, "source": "more-size"}
            out["more_size_variants"] = len([u for u in cand if u])
        else:
            out["more_size_error"] = ms.get("raw", {}).get("error") or ms.get("httpStatus")

    measured = []
    for c in sorted(pool.values(), key=lambda x: -br(x["url"])):
        prox = proxy_url(sess, c["url"])
        if not prox.get("url"):
            continue
        try:
            st, buf = fetch_head(prox["url"], sess.referer)
        except Exception as e:
            measured.append({**c, "proxy": prox["url"], "status": "ERR:%s" % e, "bytes": 0})
            continue
        measured.append({**c, "proxy": prox["url"], "status": st, "bytes": len(buf),
                         "dim": tkhd_dim(buf), "br": br(c["url"])})
    measured.sort(key=lambda m: -m["bytes"])
    out["candidates"] = ["br=%s %s %sB%s" % (m.get("br", "?"), m.get("dim") or "-", m["bytes"],
                                             " [more-size]" if m.get("source") == "more-size" else "")
                         for m in measured]
    best = next((m for m in measured if m["status"] == 200 and m["bytes"] > 1024), None)
    if best:
        out["best"] = {"br": best.get("br"), "dim": best.get("dim"), "bytes": best["bytes"],
                       "source": best.get("source", "parse"), "proxy_status": best["status"]}
    if want_dl and best:
        os.makedirs("dl", exist_ok=True)
        safe = re.sub(r'[\\/:*?"<>|\s]+', "_", str(p.get("title") or "media"))[:60]
        fp = os.path.join("dl", "%s_%s.mp4" % (safe, best.get("dim") or "%skbps" % best.get("br")))
        st, buf = fetch_head(best["proxy"], sess.referer)
        with open(fp, "wb") as f:
            f.write(buf)
        out["saved"] = {"file": fp, "bytes": len(buf), "magic": buf[4:12].decode("ascii", "ignore")}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
