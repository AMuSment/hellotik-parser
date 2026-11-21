# -*- coding: utf-8 -*-
"""X（推特）兜底路径的离线测试：不联网、不依赖真的 yt-dlp。

真实解析靠 `yt-dlp -J`，这里把它的输出换成一个固定 info dict，只验我们自己的
筛选/去重/估体积/回退逻辑。
"""
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import hellotik_dl as H


INFO = {
    "id": "1800000000000000000",
    "title": "cat.mp4",
    "uploader": "someone",
    "duration": 12.5,
    "thumbnail": "https://pbs.twimg.com/media/abc.jpg",
    "webpage_url": "https://x.com/someone/status/1800000000000000000",
    "formats": [
        # 纯音轨：要丢掉
        {"format_id": "audio", "vcodec": "none", "acodec": "mp4a", "tbr": 128,
         "url": "https://video.twimg.com/a.m4a"},
        # m3u8：同码率重复，要丢掉
        {"format_id": "hls-720", "protocol": "m3u8_native", "vcodec": "avc1",
         "height": 720, "width": 1280, "tbr": 2176, "ext": "mp4",
         "url": "https://video.twimg.com/x.m3u8"},
        {"format_id": "hls-480", "protocol": "m3u8_native", "vcodec": "avc1",
         "height": 480, "width": 854, "tbr": 832, "ext": "mp4",
         "url": "https://video.twimg.com/y.m3u8"},
        # 直链：720p 两条（同高度同码率，去重留一条）
        {"format_id": "http-720", "protocol": "https", "vcodec": "avc1", "acodec": "mp4a",
         "height": 720, "width": 1280, "tbr": 2176, "ext": "mp4",
         "filesize": 3_400_000, "url": "https://video.twimg.com/720.mp4?tag=12"},
        {"format_id": "http-720b", "protocol": "https", "vcodec": "avc1", "acodec": "mp4a",
         "height": 720, "width": 1280, "tbr": 2176, "ext": "mp4",
         "filesize": 3_400_000, "url": "https://video.twimg.com/720b.mp4?tag=12"},
        # 480p 直链：没有 filesize，靠 tbr×duration 估
        {"format_id": "http-480", "protocol": "https", "vcodec": "avc1", "acodec": "mp4a",
         "height": 480, "width": 854, "tbr": 832, "ext": "mp4",
         "url": "https://video.twimg.com/480.mp4?tag=12"},
        # 占位：mhtml 幻灯片，丢掉
        {"format_id": "storyboard", "vcodec": "none", "ext": "mhtml",
         "url": "https://video.twimg.com/sb.mhtml"},
    ],
}


class TestFormats(unittest.TestCase):
    def test_filter_and_order(self):
        cands = H.x_formats_to_cands(INFO)
        self.assertEqual([c["label"] for c in cands], ["720p", "480p"])
        self.assertEqual(cands[0]["dim"], "1280x720")
        self.assertEqual(cands[0]["size"], 3_400_000)
        self.assertTrue(cands[0]["src"].startswith("https://video.twimg.com/720"))
        for c in cands:
            self.assertEqual(c["source"], "ytdlp")
            self.assertNotIn("_h", c)

    def test_estimated_size(self):
        cands = H.x_formats_to_cands(INFO)
        low = [c for c in cands if c["label"] == "480p"][0]
        self.assertEqual(low["size"], int(832 * 1000 / 8 * 12.5))

    def test_empty(self):
        self.assertEqual(H.x_formats_to_cands({}), [])
        self.assertEqual(H.x_formats_to_cands(None), [])


class TestFromYtdlp(unittest.TestCase):
    def test_ok(self):
        with mock.patch.object(H, "ytdlp_bin", return_value="/usr/bin/yt-dlp"), \
             mock.patch.object(H, "_run_ytdlp", return_value=(INFO, "")):
            r = H.x_from_ytdlp("https://x.com/someone/status/1800000000000000000")
        self.assertTrue(r["ok"])
        self.assertEqual(r["author"], "someone")
        self.assertEqual(r["best"], 0)
        self.assertIn("pbs.twimg.com", r["cover"])

    def test_no_binary(self):
        with mock.patch.object(H, "ytdlp_bin", return_value=None):
            r = H.x_from_ytdlp("https://x.com/a/status/1")
        self.assertFalse(r["ok"])
        self.assertIn("yt-dlp", r["error"])

    def test_parser_failure(self):
        with mock.patch.object(H, "ytdlp_bin", return_value="yt-dlp"), \
             mock.patch.object(H, "_run_ytdlp", return_value=(None, "HTTP Error 404")):
            r = H.x_from_ytdlp("https://x.com/a/status/1")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "HTTP Error 404")

    def test_no_video(self):
        info = {"title": "t", "formats": [{"vcodec": "none", "url": "u"}]}
        with mock.patch.object(H, "_run_ytdlp", return_value=(info, "")):
            r = H.x_from_ytdlp("https://x.com/a/status/1")
        self.assertFalse(r["ok"])
        self.assertIn("没解析出视频流", r["error"])


class TestEnv(unittest.TestCase):
    def test_bin_from_env(self):
        with mock.patch.dict(os.environ, {"YTDLP": sys.executable}):
            self.assertEqual(H.ytdlp_bin(), sys.executable)

    def test_proxy_precedence(self):
        env = {"X_PROXY": "http://127.0.0.1:7890", "HTTPS_PROXY": "http://127.0.0.1:1080"}
        with mock.patch.dict(os.environ, env):
            self.assertEqual(H.x_proxy(), "http://127.0.0.1:7890")
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:1080"}):
            self.assertEqual(H.x_proxy(), "http://127.0.0.1:1080")

    def test_proxy_arg_passed(self):
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            return mock.Mock(returncode=0, stdout=b'{"formats": []}', stderr=b"")

        with mock.patch.object(H, "ytdlp_bin", return_value="yt-dlp"), \
             mock.patch.object(H.subprocess, "run", side_effect=fake_run), \
             mock.patch.dict(os.environ, {"X_PROXY": "http://p:1"}):
            info, err = H._run_ytdlp("https://x.com/a/status/1")
        self.assertEqual(err, "")
        self.assertEqual(seen["cmd"][:3], ["yt-dlp", "--proxy", "http://p:1"])


class TestWebuiFallback(unittest.TestCase):
    def test_phase_shape(self):
        import hellotik_webui as W

        alt = {"ok": True, "title": "cat.mp4", "author": "someone", "cover": "c.jpg",
               "candidates": [{"label": "720p", "src": "https://video.twimg.com/720.mp4",
                               "size": 100, "status": 200}], "best": 0}
        res = W._x_ytdlp_phase("https://x.com/a/status/1", alt, 0.0)
        self.assertTrue(res["ok"])
        self.assertEqual(res["platform"], "x")
        self.assertEqual(res["engine"], "yt-dlp")
        self.assertEqual(res["title"], "@someone · cat.mp4")
        self.assertEqual(res["candidates"][0]["label"], "720p")
        self.assertFalse(res["moreAvailable"])
        self.assertIn(res["sid"], W.SESSIONS)
        with W._LOCK:
            W.SESSIONS.pop(res["sid"], None)

    def test_twimg_allowed(self):
        import hellotik_webui as W

        self.assertTrue(W.allowed("https://video.twimg.com/a/720.mp4"))
        self.assertTrue(W.direct_src("https://video.twimg.com/a/720.mp4"))
        self.assertFalse(W.allowed("https://evil.example.com/a.mp4"))


if __name__ == "__main__":
    unittest.main()
