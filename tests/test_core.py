# -*- coding: utf-8 -*-
"""纯逻辑单测：AES/CBC/GCM、混淆链、平台判定、候选去重。
    python -m unittest discover -s tests -v
"""
import base64
import hashlib
import os
import sys
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import hellotik_dl as H  # noqa: E402


STD, CUS = H.STD_ALPHABET, H.CUSTOM_ALPHABET


def _alpha(b):
    """STD 字母表 -> 站方自定义字母表（服务端编码方向）"""
    return bytes(ord(CUS[STD.index(chr(c))]) if chr(c) in STD else c for c in b)


def _rev8(b):
    return b"".join(b[i:i + 8][::-1] for i in range(0, len(b), 8))


def _xor(b):
    return bytes(c ^ 90 for c in b)


def obf_body(ct):
    return _xor(_rev8(_alpha(base64.b64encode(ct))))


def obf_parse(ct):
    return base64.b64encode(obf_body(ct))


class TestAES(unittest.TestCase):
    KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                        "101112131415161718191a1b1c1d1e1f")

    def test_nist_block_vector(self):
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        aes = H.AES(self.KEY)
        self.assertEqual(aes.encrypt_block(pt), ct)
        self.assertEqual(aes.decrypt_block(ct), pt)

    def test_cbc_roundtrip(self):
        for n in (16, 64, 4096, 16400):
            key, iv, data = os.urandom(32), os.urandom(16), os.urandom(n)
            ct = H.aes_cbc_encrypt(key, iv, data)      # 带 PKCS#7 填充，可能多一块
            self.assertIn(len(ct), (n, n + 16))
            self.assertEqual(H.aes_cbc_decrypt(key, iv, ct), data)

    def test_gcm_nist_empty_plaintext(self):
        # NIST GCM Test Case 13：全零 key/IV，空明文空 AAD
        out = H.aes_gcm_encrypt(b"\x00" * 32, b"\x00" * 12, b"", b"")
        self.assertEqual(out.hex(), "530f8afbc74536b9a963b4f1c4cb738b")


class TestObfuscation(unittest.TestCase):
    def test_parse_roundtrip(self):
        plain = b'{"title":"x","videos":[]}'
        iv = os.urandom(16)
        ct = H.aes_cbc_encrypt(H.SALT, iv, plain)
        got = H.generate_output(obf_parse(ct), obf_parse(iv))
        self.assertEqual(got, {"title": "x", "videos": []})

    def test_more_size_roundtrip(self):
        token = "tok"
        plain = b'{"url":"https://v/x.mp4"}'
        iv = os.urandom(16)
        key = hashlib.sha256(token.encode()).digest()
        ct = H.aes_cbc_encrypt(key, iv, plain)
        got = H.decrypt_more_size_response(obf_body(ct).decode("latin-1"),
                                           obf_body(iv).decode("latin-1"), token)
        self.assertEqual(got, {"url": "https://v/x.mp4"})

    def test_helpers_accept_str_and_bytes(self):
        raw = os.urandom(64)
        self.assertEqual(H._rev8(raw), H._rev8(raw.decode("latin-1")))


class TestMp4(unittest.TestCase):
    def test_tkhd_dim(self):
        box = (b"\x00\x00\x00\x68" + b"tkhd" + b"\x00" * 76
               + (1080 << 16).to_bytes(4, "big") + (1920 << 16).to_bytes(4, "big")
               + b"\x00" * 12)
        self.assertEqual(H.tkhd_dim(box), "1080x1920")
        self.assertIsNone(H.tkhd_dim(b"\x00" * 200))

    def test_total_size(self):
        self.assertEqual(H.total_size({"content-range": "bytes 0-9/12345"}), 12345)
        self.assertEqual(H.total_size({"content-length": "999"}), 999)
        self.assertEqual(H.total_size({}), 0)


class TestHelpers(unittest.TestCase):
    def test_extract_url_from_share_text(self):
        text = "7.92 复制打开抖音 https://v.douyin.com/iAbCdEf/ 看看【某人的作品】"
        self.assertEqual(H.extract_url(text), "https://v.douyin.com/iAbCdEf/")
        self.assertEqual(H.extract_url("https://x.com/a/status/1?a=1&amp;b=2"),
                         "https://x.com/a/status/1?a=1&b=2")
        self.assertEqual(H.extract_url("没有链接"), "")

    def test_detect_platform(self):
        self.assertEqual(H.detect_platform("https://v.douyin.com/x/")[0], "douyin")
        self.assertEqual(H.detect_platform("https://www.xiaohongshu.com/x")[0], "rednote")
        self.assertEqual(H.detect_platform("http://xhslink.com/a/b")[0], "rednote")
        self.assertEqual(H.detect_platform("https://www.kuaishou.com/short-video/1")[0],
                         "kuaishou")
        self.assertEqual(H.detect_platform("https://x.com/a/status/1")[0], "x")
        self.assertEqual(H.detect_platform("https://unknown/1")[0], "douyin")

    def test_br_and_label(self):
        self.assertEqual(H.br_of("https://c/x.mp4?br=2400&a=1"), 2400)
        self.assertEqual(H.quality_label("https://c/x.mp4?br=2400"), "2400kbps")
        self.assertEqual(H.quality_label("https://c/x.mp4"), "原始档")
        self.assertEqual(H.quality_label("https://c/x.mp4", "720p"), "720p")

    def test_dedupe_and_pick(self):
        cands = [{"size": 300}, {"size": 0}, {"size": 300}, {"size": 200}]
        out = H.dedupe_by_size(cands)
        self.assertEqual([c["size"] for c in out], [300, 200, 0])
        ok = [{"status": 200, "size": 4096}, {"status": 0, "size": 0}]
        self.assertEqual(H.pick_best(ok), 0)
        self.assertIsNone(H.pick_best([{"status": 500, "size": 10}]))

    def test_pool_from_payload(self):
        payload = {"videos": [{"url": "https://v/main.mp4",
                               "video_fullinfo": [{"url": "https://v/hd.mp4", "type": "720p",
                                                   "size": "1234"}]}]}
        pool = H.pool_from_payload(payload)
        self.assertEqual(pool["https://v/hd.mp4"]["label"], "720p")
        self.assertEqual(pool["https://v/hd.mp4"]["sizeHint"], 1234)
        self.assertIn("https://v/main.mp4", pool)


if __name__ == "__main__":
    unittest.main()
