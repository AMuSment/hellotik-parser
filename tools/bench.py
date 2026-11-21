#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""性能基准：新旧实现同一台机器上对比 AES-CBC / 混淆链 / GCM / 整链解密。

    python tools/bench.py                 # 只测当前实现
    python tools/bench.py --old old.py    # 同时测一份旧实现（git show HEAD:hellotik_dl.py > old.py）

输出 markdown 表格，可直接贴进 docs/OPTIMIZATION.md。
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def timeit(fn, repeat=5, number=1):
    """取 repeat 轮里最快的一轮平均耗时（毫秒）"""
    best = None
    for _ in range(repeat):
        t0 = time.perf_counter()
        for _ in range(number):
            fn()
        dt = (time.perf_counter() - t0) * 1000 / number
        best = dt if best is None else min(best, dt)
    return best


# ---- 造一份服务端会发的加密体（编码方向：字母表置换 -> 8 字节反转 -> XOR90） ----
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
CUS = "ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw9876543210-_"
_S2C = {STD[i]: CUS[i] for i in range(64)}
_C2S = {v: k for k, v in _S2C.items()}


def _shuffle(s):
    return "".join(_S2C.get(ch, ch) for ch in s)


def encode_payload(ct):
    b = _shuffle(base64.b64encode(ct).decode("latin-1")).encode("latin-1")
    b = b"".join(b[i:i + 8][::-1] for i in range(0, len(b), 8))
    return bytes(c ^ 90 for c in b)


def decode_payload(raw, mod):
    """解码链本身（旧实现只吃 str，新实现两者都吃）"""
    if isinstance(raw, bytes) and not hasattr(mod, "_as_bytes"):
        raw = raw.decode("latin-1")
    return mod._b64(mod._unshuffle(mod._rev8(mod._xor90(raw))))


def fixtures(mod):
    """用新实现造密文，新旧实现都吃同一份输入，保证公平"""
    iv4, iv11 = b"0" * 16, b"1" * 16
    plain4k = bytes((i * 31) % 256 for i in range(4096))
    plain11k = bytes((i * 17) % 256 for i in range(11 * 1024))
    ct4k = mod.aes_cbc_encrypt(mod.SALT, iv4, plain4k)
    ct11k = mod.aes_cbc_encrypt(mod.SALT, iv11, plain11k)
    ct4k, ct11k = ct4k[:4096], ct11k[: 11 * 1024]
    obj = {"title": "基准", "url": "https://v26-kefu.douyinvod.com/x.mp4",
           "videos": [{"url": "https://v26-kefu.douyinvod.com/x.mp4"}],
           "pad": "x" * 4096}
    ct_json = mod.aes_cbc_encrypt(mod.SALT, iv4, json.dumps(obj).encode())
    mkey = hashlib.sha256(b"token").digest()
    more_json = json.dumps({"url": "https://v26-colds.douyinvod.com/orig.mp4?br=3500",
                            "variants": [{"url": "https://v26-colds.douyinvod.com/v%d.mp4" % i}
                                         for i in range(20)],
                            "pad": "x" * 11000}).encode()
    ct_more = mod.aes_cbc_encrypt(mkey, iv11, more_json)
    return {
        "iv4": iv4, "iv11": iv11, "ct4k": ct4k, "ct11k": ct11k,
        "more_data": encode_payload(ct_more), "more_iv": encode_payload(iv11),
        "parse_data": base64.b64encode(encode_payload(ct_json)).decode("ascii"),
        "parse_key": base64.b64encode(encode_payload(iv4)).decode("ascii"),
    }


def bench(mod, label, F, rows):
    checks = [
        ("CBC 解密 4KB（单次解析）", lambda: mod.aes_cbc_decrypt(mod.SALT, F["iv4"], F["ct4k"]), 20),
        ("CBC 解密 11KB（整档响应）", lambda: mod.aes_cbc_decrypt(mod.SALT, F["iv11"], F["ct11k"]), 10),
        ("混淆链 11KB（XOR+反转+字母表）", lambda: decode_payload(F["more_data"], mod), 200),
        ("more-size 整链解密（11KB）",
         lambda: mod.decrypt_more_size_response(F["more_data"].decode("latin-1"),
                                                F["more_iv"].decode("latin-1"), "token"), 10),
        ("parse 整链解密（4KB 明文）",
         lambda: mod.generate_output(F["parse_data"], F["parse_key"]), 10),
        ("GCM 加密 140B（请求体）",
         lambda: mod.aes_gcm_encrypt(b"k" * 32, b"iuid00000000",
                                     b'{"requestURL":"https://v.douyin.com/x/"}'[:140]), 200),
    ]
    for name, fn, number in checks:
        cell = rows.setdefault(name, {})
        try:
            cell[label] = timeit(fn, 5, number)
        except Exception as e:      # 旧实现签名/行为不同就标 n/a，别让基准挂掉
            cell[label] = "n/a (%s)" % type(e).__name__


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--old", help="旧实现文件路径（默认取 git HEAD 版本）")
    ap.add_argument("--json", action="store_true", help="输出 JSON 便于脚本处理")
    args = ap.parse_args()

    new = load(os.path.join(ROOT, "hellotik_dl.py"), "hellotik_new")
    F = fixtures(new)
    rows = {}
    bench(new, "new", F, rows)

    old_path = args.old
    if not old_path:
        try:
            blob = subprocess.run(["git", "show", "HEAD:hellotik_dl.py"], cwd=ROOT,
                                  capture_output=True, check=True).stdout
            old_path = os.path.join(ROOT, ".verify", "old_h.py")
            os.makedirs(os.path.dirname(old_path), exist_ok=True)
            with open(old_path, "wb") as f:
                f.write(blob)
        except Exception:
            old_path = None
    has_old = bool(old_path and os.path.exists(old_path))
    if has_old:
        bench(load(old_path, "hellotik_old"), "old", F, rows)

    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return

    print("| 场景 | 旧实现 | 新实现 | 提速 |")
    print("| --- | ---: | ---: | ---: |")
    for name, vals in rows.items():
        o, n = vals.get("old"), vals.get("new")
        f = lambda v: ("%0.2f ms" % v) if isinstance(v, float) else (v or "—")
        sp = "%0.1f×" % (o / n) if isinstance(o, float) and isinstance(n, float) and n else "—"
        print("| %s | %s | %s | %s |" % (name, f(o) if has_old else "—", f(n), sp))


if __name__ == "__main__":
    main()
