# hellotik-parser

多平台短视频解析 / 无水印下载器，自带本地 WebUI。

支持 **抖音 · 小红书 · 快手 · X（推特）** 的分享链接，粘进网页就能出各档位直链：预览、下载、复制直链、按需重编码压缩体积。

抖音／小红书／快手走 `hellotik.app` 的票据 + 加密解析协议（本项目对该协议做了完整逆向，见 [`docs/REA_report.md`](docs/REA_report.md)）；X 走另一条路（见下文），因为 X 系主机在境内直连不通。

```
┌──────────────┐   POST /api/parse   ┌───────────────────────┐
│  浏览器页面   │ ──────────────────► │  hellotik_webui.py    │
│ webui/index  │ ◄── 基础档位(秒回) ── │  (标准库 HTTP，无框架) │
│   .html      │                     │                       │
│              │   POST /api/more    │  抖音系: gate → AES-GCM│
│              │ ◄─ 最高画质(补齐) ─── │  → parse → more-size  │
│              │                     │  X: x2twitter/snapcdn │
└──────────────┘   GET /api/file     └───────────────────────┘
                    GET /api/img               │
                    POST /api/compress        ▼
                                        ffmpeg 重编码 + 缓存
```

## 特性

- **四种平台，一个页面**：平台按链接自动识别，不用选。
- **两段式解析**：抖音系先 2 秒出基础档位（540p/720p），后台再追站方 `more-size` 拿到原始高清（实测 1080p、约 15 Mbps），页面就地补行，不用干等。
- **档位表**：画质、体积、分辨率、时长一目了然，最佳档自动高亮。
- **下载避开防盗链**：源 CDN 直连 403，服务端统一换成站方代理直链再流式吐给浏览器。
- **压缩画质**：内置调 ffmpeg 重编码（360p/480p/720p/1080p 四档 CRF 预设），带结果缓存，省 66%～94%。
- **局域网 / 公网可用**：`--public` 一键开访问口令 + 每 IP 限流；配 `cloudflared` 可出公网地址（零入站端口）。
- **断点续传 / 边下边播**：`/api/file`、`/api/cfile` 支持 `Range`（206 + `content-range`）与 `HEAD`，浏览器可直接拖动进度条、下载器可续传。
- **粘贴整段分享文案**：带一堆中文和表情的「复制打开抖音…」也能直接解析，服务端只取里面那条链接。
- **零第三方依赖**：Python 端纯标准库，自带 AES-256（CBC/GCM）实现，`pip install` 都不需要。

## 实测

| 平台 | 输入 | 结果 |
|---|---|---|
| 抖音 | `v.douyin.com/L4FJNR3/` | 2 档基础 + `more-size` 原始档 19,027,256 B / 1080×1920 / 10.13s |
| 抖音 | `v.douyin.com/L4NpDJ6/` | 原始档 12,890,778 B / 1080×1916 / 7.51s |
| X | `x.com/CTVJLaidlaw/status/1600649710662213632` | 2.5s 出 6 档（2 个视频 × 1280p/852p/568p），最高 16.3 MB / 720×1280 / 113s |
| X | `x.com/historyinmemes/status/1790637656616943991` | 2.4s 出 3 档：728×720 / 364×360 / 272×270，时长 15.5s |

压缩示例：19 MB 的 1080×1920 原始档 → 720p 1.12 MB（省 94%，12.8s）；1.45 MB 档 → 720p 493 KB（省 66%，5.4s）。

## 快速开始

### 1. 网页版

```bash
# 只有本机能访问
python hellotik_webui.py --port 8765

# 挂到局域网（自动生成或指定访问口令）
python hellotik_webui.py --public --token 我的口令
```

打开 `http://127.0.0.1:8765/`（局域网用 `http://<本机IP>:8765/?k=我的口令`，口令会写进 cookie，之后不用再带）。

Windows 双击即用：

- `start-lan.cmd` —— 只开局域网，口令存 `webui_token.txt` 复用
- `start-public.cmd` —— 局域网 + `cloudflared` 临时公网隧道（需 `bin/cloudflared.exe`）

### 2. 命令行

```bash
# Python 版
python hellotik_dl.py <分享链接|分享文案>                 # 只解析，打印档位
python hellotik_dl.py <链接> -m                          # 追最高画质（more-size）
python hellotik_dl.py <链接> -m -d                       # 追最高画质并下载到 dl/
python hellotik_dl.py <链接> -m -d --out D:/videos       # 指定下载目录
python hellotik_dl.py <链接> --quality 720p              # 指定档位（label/分辨率/码率都支持子串匹配）
python hellotik_dl.py <链接> --json                      # 机器可读输出（stdout 只有 JSON）
python hellotik_dl.py <链接> --no-measure                # 不逐档探测体积/分辨率，最快
python hellotik_dl.py <链接> --dump-parse                # 额外打印解密后的原始 payload
python hellotik_dl.py <链接> --concurrency 4 --timeout 30

# Node 版（只需 node:crypto）
node hellotik_dl.mjs <分享链接> --more-size --download
```

两个版本对同一链接输出一致，AES 实现分别用 Python 标准库与 `node:crypto`，NIST 测试向量均通过。

### 3. 可选依赖

| 能力 | 需要 | 说明 |
|---|---|---|
| 压缩画质 | `ffmpeg` | 放 `bin/ffmpeg/bin/ffmpeg.exe` 或加进 PATH，启动时会自检并打印 |
| 公网隧道 | `cloudflared` | 放 `bin/cloudflared.exe`；纯出站连接，不开入站端口 |
| 走代理直连 X | `yt-dlp` | x2twitter/savetwitter 都失败时自动回退到本机 `yt-dlp -J`（需能出网，境内配代理：`X_PROXY=http://127.0.0.1:7890`） |

## 项目结构

```
hellotik_dl.py          抖音/小红书/快手 解析库 + CLI（纯标准库，含 AES-CBC/GCM 实现）
hellotik_dl.mjs         同上，Node ESM 版
hellotik_webui.py       WebUI 服务端（四种平台、压缩、口令、限流）
webui/index.html        前端单页（无外部依赖，深色主题）
webui/cdp_test.mjs      CDP 无头浏览器端到端测试（解析链路）
webui/cdp_compress.mjs  同上（压缩链路）
tests/                  离线单测 + 端到端（自带假 hellotik，不联网）
tools/bench.py          性能基准：新旧实现同机对比 AES / 混淆链 / 整链解密
tools/mp4_probe.mjs     裸 mp4 探针：逐 trak 报 codec / tkhd 分辨率 / mvhd 时长
tools/verify_more_size.mjs  more-size 链路验证
docs/REA_report.md      完整逆向报告（协议细节、实测证据、踩坑清单）
docs/OPTIMIZATION.md    这一轮优化的实测数据与改动清单
start-lan.cmd           一键：局域网
start-public.cmd        一键：局域网 + 公网隧道
```

## 性能

AES 与响应混淆链都改成了字节级查表，同一台机器上（`python tools/bench.py` 可复现）：

| 场景 | 旧实现 | 现在 | 提速 |
|---|---:|---:|---:|
| CBC 解密 4KB（单次解析） | 182.75 ms | 8.22 ms | 22.2× |
| parse 整链解密 | 192.00 ms | 11.30 ms | 17.0× |
| more-size 整链解密（11KB） | 549.63 ms | 26.03 ms | 21.1× |
| GCM 加密请求体 | 1.99 ms | 0.31 ms | 6.3× |

网络侧每档探测从 3～4 个请求降到 1～2 个（一次 Range 请求同时拿状态、总体积、分辨率），
换链结果做 300s 缓存。改动细节、边界修复与测试清单见 [`docs/OPTIMIZATION.md`](docs/OPTIMIZATION.md)。

```bash
python -m unittest discover -s tests -v    # 33 项，全部离线
```

## 技术摘要

### 抖音 / 小红书 / 快手 —— `hellotik.app` 协议

三个平台共用同一套协议，**平台靠 Referer 区分**，请求体逐字一致。

1. **取票据（gate）**
   `POST /api/gate-e5eea8` `{"requestURL":"<分享链接>","isBatch":false,"mode":"single"}`
   → `{tk_e5eea8, sd_e5eea8, ex_e5eea8}`，同时下发匿名会话 cookie `parse_sid`。

2. **加密请求体（AES-256-GCM）**
   密钥 = `SHA-256("<ticket>:<seed>")` 的**原始 32 字节**（不是 hex 字符串），12 字节随机 IV，
   明文是解析参数 `{requestURL, isMobile, isoCode, adType, uwx_id}`。

3. **解析（parse）**
   `POST /api/parse` → `{status, encrypt:true, data, key, qualityTier}`。
   响应是双重混淆 + AES-256-CBC：
   `base64 decode → 每字符 XOR 90 → 每 8 字符块反转 → 自定义字母表还原 → AES-CBC`
   其中 CBC 密钥是硬编码 32 字符常量。

4. **追最高画质（more-size）**
   `POST /api/more-size`，头带解析回执里的 `X-More-Size-Token`，**并且必须带 gate 下发的 `parse_sid` cookie**（不带 → 403 `MORE_SIZE_PROOF_MISMATCH`）。
   该 token 是 JWT，payload 里 `inputHash = SHA-256(原始请求链接)`、`subjectHash = SHA-256(parse_sid)`，TTL 300 秒 —— 服务端用它证明"这次 more-size 确实是刚才那次解析的延续"。
   这条响应的解密链条顺序与 parse 相反（先 XOR 再 base64），密钥 = `SHA-256(token)`。

5. **下载**
   源 CDN 有 Referer 防盗链，直连 403。`POST /api/download-proxy-url` 换成站内代理直链后即可下载（支持 Range）。

> 路由名与字段名**每周轮换**（当前为 `2026w12` 的 `e5eea8` 系列，回退 profile 为 `2026w03` 的 `4a160a`）。字段名写死在站点 JS 里，协议本身不变，轮换只需改常量。

### X（推特）

`x.com` / `api.x.com` / `video.twimg.com` / `pbs.twimg.com` 在境内直连全部超时，所以 `yt-dlp` 一类直连方案在本机拿不到任何元数据。走通的路是：

1. `POST https://x2twitter.com/api/ajaxSearch`（`q=<推文链接>&lang=en`）→ 返回一段 HTML，每条媒体一块，含缩略图与各档位下载按钮；
2. 按钮的 `href` 是 `https://dl.snapcdn.app/get?token=<JWT>`，JWT 第二段解出真实地址与文件名，**有效期 1 小时**；
3. `dl.snapcdn.app` 是 Cloudflare 前置的**服务端代理**，它自己回源 `video.twimg.com` 再把文件吐给客户端（支持 Range）。**所以本机不需要能连上 X。**

`savetwitter.net` 是同一后端的镜像，代码里做成互备。分辨率直接取真实地址路径里的 `WxH`（已与 ffprobe 实测一致）；作者名与时长从 `api.fxtwitter.com` 回填。

**兜底链路（v2）**：两个第三方站都不可用时（改接口、Cloudflare 挡、单点挂掉），自动改用本机 `yt-dlp -J` 解析，按分辨率/码率列出各档位，直链走 `video.twimg.com`：

```bash
pip install -U yt-dlp                    # 或把 yt-dlp.exe 放进 bin/
export X_PROXY=http://127.0.0.1:7890     # 境内必配；也认 HTTPS_PROXY / ALL_PROXY
python hellotik_dl.py "https://x.com/<user>/status/<id>"
```

WebUI 里同样生效：`/api/parse` 先走第三方，失败才回退（返回体多了 `"engine": "yt-dlp"`）；`/api/status` 的 `ytdlp` 字段表示本机有没有找到可执行文件。CLI 的 X 链接**只走** yt-dlp（不经过 hellotik 协议），所以必须先装好并配代理。

## 限制

- **抖音系的配额**：服务端按 IP 判定，高频调用后 gate 会返回 `429 TICKET_IP_RESTRICTED`，冷却十几秒到几分钟；页面上会自动进入倒计时并禁用按钮。批量采集请改用直连方案（如 [yt-dlp](https://github.com/yt-dlp/yt-dlp)、[Douyin_TikTok_Download_API](https://github.com/Evil0ctal/Douyin_TikTok_Download_API)）。
- **小红书**：协议与抖音完全一致、平台靠 Referer 区分（已由回执 `platform` 字段实证），但现代小红书笔记分享链接带 `xsec_token`，手头没有可用的真实样本做端到端实测。
- **X 依赖第三方**：默认解析与文件都经过 x2twitter / savetwitter / snapcdn，是单点；它们改接口这条通路就断。已加 `yt-dlp` 兜底（需能出网/代理），两条都不通时只能等对方恢复。直链 1 小时过期，过期重新解析即可。
- **压缩档不是原档**：本机重编码，体积小很多但画质不可比，要收藏请用原始档。
- 只做**单条解析**，不做批量任务队列。

## 关于逆向证据

仓库不含 `hellotik.app` 的原始 JS chunk（抓取样本）——它们文件名是构建哈希、属于第三方站点代码，且报告中已引用关键片段与行号。需要复现时，按 `docs/REA_report.md` 里的说明从站点按 `webpack` chunk 映射表取即可。

## 免责声明

仅供学习与研究协议实现之用。下载内容请遵守来源平台的服务条款与著作权规定，勿用于商业传播。

## License

[MIT](LICENSE)
