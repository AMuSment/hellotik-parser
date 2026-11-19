# hellotik.app 解析能力 REA 报告（抖音 / 小红书 无水印下载）

- 目标：`https://www.hellotik.app/zh/douyin`（同源 `:rednote` 小红书、`:kuaishou` 快手）
- 方式：**纯静态逆向**（下载站点 JS chunk 阅读实现）+ 本地脚本复现验证；未使用调试器附加
- 日期：2026-11-16
- 结论：**协议已完整还原并在本地跑通端到端**，拿到抖音视频 1080p 原始档直链并成功下载（见「实测证据」）
- 产物：
  - `hellotik_dl.mjs` —— Node 版实现（ESM，零依赖，内置 `node:crypto`）
  - `hellotik_dl.py` —— Python 版实现（**纯标准库**，自带纯 Python AES-256/CBC/GCM）
  - `dl/` —— 实测下载产物

---

## 1. 站点性质

Next.js 应用，服务端 API 路由 `/api/*`（`server: wafcdn`）。前端宣称"完全免费不限次数/无需注册/无水印"，实际有**浏览器端配额 + IP 级限流 + 票据一次性**三层约束。支持的平台由**请求的 Referer** 区分（`/zh/douyin`、`/zh/rednote`、`/zh/kuaishou`），请求体字段三个平台完全一致。

## 2. 端点清单

| 方法 | 端点 | 作用 |
|---|---|---|
| POST | `/api/<authRoute>`（当前 `gate-e5eea8`） | 取解析票据，**同时下发 `parse_sid` 匿名会话 cookie** |
| POST | `/api/parse` | 主解析（加密请求体 / 加密响应体） |
| POST | `/api/more-size` | 更高码率（1080p 原始档），需 `X-More-Size-Token` |
| POST | `/api/download-proxy-url` | 源直链 → 站内代理直链（绕开源 CDN 的 Referer 防盗链） |
| POST | `/api/parse-entitlement-status` | 配额/权益查询（轮询） |
| POST | `/api/reward-qrcode`、GET `/api/wxqrcode`、POST `/api/reward-qr-event` | 扫码激励解锁高清 |
| POST | `/api/download-events`、`/api/events/parse`、`/api/events/ultra-hd`、`/api/conversion/funnel` | 埋点 |
| POST | `/account/api/uwx/generate-id` | 设备指纹（直连 404，用本地降级格式仍被接受） |
| GET | `https://user.hellotik.app/getip/geoip?minimal=1` | 出口 IP 地理信息 |

## 3. 协议还原

### 3.1 票据 profile（写死在 chunk 2716，无外部配置拉取）

`activeProfileId = "2026w12"`，字段名每周轮换：

| profile | authRoute | 票据字段 | 解析请求字段 |
|---|---|---|---|
| 2026w12（激活） | `gate-e5eea8` | `tk_e5eea8` / `sd_e5eea8` / `ex_e5eea8` | `pl_e5eea8` / `iv_e5eea8` / `vr_e5eea8` |
| 2026w03（回退） | `gate-4a160a` | `tk_4a160a` / … | `pl_4a160a` / … |

脚本已做双 profile 探测，路由轮换后只需在一旁补新值。

### 3.2 请求加密（AES-256-GCM）

```
1. POST /api/gate-e5eea8  body {"requestURL": <分享链接>, "isBatch": false, "mode": "single"}
   -> {"success": true, "tk_e5eea8": <ticket>, "sd_e5eea8": <seed>, "ex_e5eea8": <exp>}
   -> Set-Cookie: parse_sid=<22位 base62>; Path=/; Max-Age=2592000; Secure; HttpOnly; SameSite=lax

2. key = SHA-256(`${ticket}:${seed}`)   // 原始 32 字节，不是十六进制字符串
   iv  = 12 字节随机
   ct  = AES-256-GCM(key, iv, JSON.stringify(params))
   POST /api/parse body {tk_e5eea8: ticket, pl_e5eea8: b64(ct||tag), iv_e5eea8: b64(iv), vr_e5eea8: 1}
```

解析参数：`{requestURL, isBatch:false, parseMode:"single", isMobile, isoCode:"CN", adType:"adsense", uwx_id, pagePath, externalRequestId, qualityTier:"hd"}`。`uwx_id` 缺失时服务端返回 `400 MISSING_DEVICE_ID`。

### 3.3 响应解密 —— 两条不同的混淆链（易踩坑）

站点有**两套**解码器，混淆顺序不同：

**A. `/api/parse` 响应（chunk 2261 / module 62261 `generateOutput(data, key, salt)`）**
```
明文 = AES-256-CBC-Dec(
          key = salt(硬编码 "93838338562359368888868323563256"，32 字符),
          iv  = b64( unshuffle( rev8( xor90( latin1(b64decode(key)) ) ) ) ),
          ct  = b64( unshuffle( rev8( xor90( latin1(b64decode(data)) ) ) ) ) )
```
即 **先 base64 解码 → XOR 0x5A → 每 8 字符块反转 → 自定义字母表还原**。

**B. `/api/more-size` 响应（chunk 951 / module 60951 `decryptMoreSizeResponse(data, iv, token)`）**
```
明文 = AES-256-CBC-Dec( key = SHA-256(token), iv, ct )
      其中 data / iv 直接做  unshuffle( rev8( xor90(字符串) ) )  —— 不先 base64 解码
```

两个变换原语：
- `xor90`：逐字符 `charCode ^ 90`
- `rev8`：每 8 个字符为一组内部反转
- `unshuffle`：字母表替换，`CUSTOM = "ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw9876543210-_"`（63 字符）下标 `i` → 标准表 `STD[i]`

### 3.4 更高码率的证明令牌（`moreSizeToken`）

`/api/parse` 明文里带 `moreSizeToken = "ms1.<base64url payload>.<sig>"`，payload 形如：
```json
{"v":1,"jti":"…","inputHash":"…","subjectHash":"…","issuedAt":1794767746468,"expiresAt":1794768046468}
```
TTL 300 秒。已对冲验证：
- `inputHash == base64url(SHA-256(解析时传入的原始分享串))` —— **必须逐字节相同**，否则 `MORE_SIZE_PROOF_MISMATCH`
- `subjectHash == base64url(SHA-256(parse_sid cookie 值))` —— 所以 **gate 拿到的 cookie 必须一路带着**

请求：`POST /api/more-size`，头 `X-More-Size-Token: <moreSizeToken>`，体 `{"input": <原始分享串>}`。返回 `{url, redirected:true, variants:[…6 条]}`，变体以 `&br=` 区分码率，**无 `br` 参数的那条体积最大（= 1080p 原始档）**。

### 3.5 防盗链与代理

源 CDN（`*.douyinvod.com`）直连 **403**（校验 Referer），必须 `POST /api/download-proxy-url {"url":…}` 换得
`https://data.hellotik.app/v1/download/video?token=<JWT(url+ts)>`，该代理直链可直接下载完整文件。

### 3.6 配额与限制

- 未登录浏览器：按累计成功数分档，每天 5–10 次免费，超出需扫码激励解锁（`deviceClass=mobile|member|batch` 则可免）
- 单 IP：每天 1000 次（文案"您今天已经超过1000次了"）
- `rate_limited` 约 10 分钟自恢复；票据一次性（`used_ticket`）
- 其它错误码：`missing_ticket / invalid_ticket / expired_ticket / ticket_subject_mismatch / ticket_request_mismatch / invalid_envelope / decrypt_failed / feature_disabled / parse_v2_disabled / parse_v3_disabled / parse_version_not_allowed`

## 4. 实测证据

| 分享链接 | 标题 | parse 档位 | more-size 最优 | 探针结果 |
|---|---|---|---|---|
| `v.douyin.com/L4FJNR3/` | 骑白马的也可以是公主#百万转场变身 | 540p 1,712,341B / 720p 3,311,062B | **19,027,256B** | `avc1 1080x1920` + `mp4a`，10.13s |
| `v.douyin.com/L4NpDJ6/` | 让你在几秒钟之内记住我 | 540p 844,227B / 720p 1,454,940B | **12,890,778B** | `avc1 1080x1916` + `mp4a`，7.51s |
| `www.xiaohongshu.com/explore/66bf76a3…` | —（上游失效） | — | — | 服务端回执 `platform:"xiaohongshu"`, `UPSTREAM_PARSE_FAILED` |

补充观测：
- `UPLOAD` 直链直连 403（372B，防盗链证实）；经代理下载 200，magic `ftypisom`
- 回执字段暴露 `client_ip` / `country_code:CN` / `page_path` —— **`page_path` 由 Referer 决定**，小红书测试中回执确认为 `/zh/rednote` 且 `platform:"xiaohongshu"`，即 **平台路由由 Referer 控制已被服务端证实**

## 5. 小红书（rednote）路径

rednote 页组件构造的请求体与抖音**完全一致**（`{requestURL,isMobile,isoCode,adType,uwx_id}`），不含平台字段 → 平台由 Referer `/zh/rednote` 判定（已由回执中的 `platform:"xiaohongshu"` 证实）。因此走同一套 gate → parse → `generateOutput` 链路。

未完成的部分：**缺一条真实有效的小红书分享链接**（现代小红书笔记需要 `xsec_token`，公开检索拿不到有效样本）。手上有真实分享链接时：

```bash
python hellotik_dl.py "https://xhslink.com/xxxxx"  --more-size
node   hellotik_dl.mjs "https://xhslink.com/xxxxx" --more-size
```
脚本按 URL 自动切 `platform=rednote` 与 Referer。

## 6. GitHub 同类项目对比（按 star）

| 项目 | star | 定位 |
|---|---|---|
| `Evil0ctal/Douyin_TikTok_Download_API` | 21413 | 自托管抖音/TikTok/B站采集 + 无水印下载 API，支持 MCP、Docker 一键部署 |
| `putyy/res-downloader` | 21304 | 视频号/小程序/抖音/快手/小红书/直播流/m3u8/音乐 资源下载 |
| `JoeanAmier/XHS-Downloader` | 13300 | 小红书链接提取 / 作品采集 |
| `arnoldhao/xiadown` | 758 | 下载工具 |
| `NEORUAA/XHS_Downloader_Android` | 637 | 小红书无水印原图（安卓） |
| `xixihhhh/hotclip` | 464 | AI 剪辑 / 直播切片 |
| `zhugezifang/Awesome-xiaohongshu-download-Tools` | 286 | 小红书下载工具合集索引 |
| `missuo/DouyinParsing` | 94 | 抖音去水印专项 |
| `icekale/rednote-downloader` | 77 | Docker 自托管小红书下载 |
| `helson-lin/douyin_no_watermark` | 31 | 抖音去水印 |
| `yxxbc/tiktok-douyin-dl` | 24 | 跨平台 GUI |
| `Devincool/shortvideos-collector` | 4 | CDP 采集 → 无水印 → whisper 转写 |
| `HuanNan520/dyfetch` | 3 | iesdouyin 分享页 + 移动 UA（带 Claude Code skill） |

**与本实现的关系**：上面这些项目解决的是"**直接从抖音/小红书官方接口**去水印"，走的是 `iesdouyin` 分享页 / 官方 Web API + 签名；本实现解决的是"**从第三方解析站 hellotik 拿结果**"，即把该站自己的票据协议与双层混淆还原，二者可互为备份（官方接口签名失效时可切站内路径，反之亦然）。

## 7. 复现要点 / 踩坑清单

1. 请求体 AES-GCM 的 key 是 `SHA-256("tk:sd")` 的**原始 32 字节**，不是 hex 文本 —— 传 hex 会 `invalid_envelope`。
2. `/api/parse` 与 `/api/more-size` 的响应混淆顺序**不同**（先 base64 vs 先 XOR），混用必得乱码。
3. `more-size` 必须带 gate 的 `parse_sid` cookie，且 `input` 与解析时逐字节一致 —— 这是 403 `MORE_SIZE_PROOF_MISMATCH` 的唯一原因。
4. 源 CDN 直链一律 403，必须换站内代理。
5. 路由名/字段名按周轮换（当前 `e5eea8` = 2026w12）。
6. MP4 分辨率探针：`tkhd` 盒体为 `[4B size][4B type][载荷]`，v0 的宽高在 **类型串位置 +80/+84**；且需跳过音轨（宽高为 0）那条。

## 8. 脚本用法

```bash
# Node 版（零依赖）
node hellotik_dl.mjs "https://v.douyin.com/xxxx/" --more-size --download --json

# Python 版（纯标准库，自带 AES-256/CBC/GCM）
python hellotik_dl.py "https://v.douyin.com/xxxx/" --more-size --download
```

选项：`--more-size` 追加更高码率候选池；`--download` 下载最优档到 `dl/`；`--json` 输出 JSON。

Python 版正确性校验：内置 AES-256 与 GCM 已对 **NIST 测试向量**通过（ECB `8ea2b7ca516745bfeafc49904b496089`、GCM tag `530f8afbc74536b9a963b4f1c4cb738b`、GCM 单块 `cea7403d4d606b6e074ec5d3baf39d18…`），且与 Node 版对同一链接输出一致（1080x1920 / 19,027,256B）。

> 说明：本项目为协议研究与本地复现，请自行确认对目标内容的使用权限。

## 9. 本地 WebUI（`hellotik_webui.py` + `webui/index.html`）

把上面的协议封装成网页界面，服务端只用 Python 标准库（复用 `hellotik_dl.py`），前端是单文件、无外部依赖。

```bash
# 启动（本机）
python hellotik_webui.py --port 8765        # -> http://127.0.0.1:8765
python hellotik_webui.py --port 8766 --fixture            # 演示：回放一条真实结果，不请求站方
python hellotik_webui.py --port 8766 --fixture --fixture-fail   # 演示：回放限流报错 + 冷却倒计时
```

路由：

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/` | 前端页面 |
| POST | `/api/parse` | **阶段一**：gate + parse，1.8–2.7s 返回标题/封面/基础档位，并建立服务端会话 `sid` |
| POST | `/api/more` | **阶段二**：more-size + 逐档体积/分辨率并发探测，返回完整档位表 |
| POST | `/api/resolve` | 一次性跑完两阶段（脚本/CLI 用） |
| GET | `/api/file?u=&name=` | 服务端换链后流式下载（`Content-Disposition: attachment`，RFC5987 中文名） |
| GET | `/api/img?u=` | 封面代取（源站 Referer 防盗链） |
| GET | `/api/status` | 健康检查 |

### 9.1 为什么要两阶段

逐阶段实测（`v.douyin.com/L4FJNR3/`）：`uwx` 0.47s + `parse` 1.47s + **`more-size` 4.31s（站方上游延迟，不可压）** + 换链 3.02s(串行) + 体积探测 2.69s + 分辨率探测 5.56s。

- 换链 `POST /api/download-proxy-url` **不依赖 cookie**（0.24s），因此可并发 —— 串行 3.0s → 并行 ≈1s
- 体积与分辨率探测放进**同一个并发轮次**（原先串行两轮）
- 分辨率探测改为**头 64KB 与尾 256KB 并发**：faststart 档命中头部，非 faststart 的原始档必须看尾部（实测原始档头 524KB 也拿不到 `tkhd`）

结果：单接口串行 36.7s → **阶段一 1.8–2.7s 先出可用结果，阶段二 9.6s 补齐最高画质**。

### 9.2 浏览器实测（CDP 驱动无头 Chrome）

| 场景 | 观测 |
|---|---|
| 成功路径（fixture 回放，真实浏览器） | 1.6s：2 行基础档位 + "正在追取更高画质" 骨架行 + 提示语；4.9s：4 行完整档位（原始档 `12.3 MB / 1080x1916` 高亮"最佳"）、封面已加载、平台徽章"识别为：抖音"、每行「下载 / 复制直链」 |
| 限流路径（回放 `429 / TICKET_IP_RESTRICTED`） | 页面提示"解析失败：站方限流，稍等十几秒再点一次（…）（TICKET_IP_RESTRICTED）"，按钮进入 `限流冷却 45s` → `限流冷却 42s` 倒计时并禁用 |
| 真实接口（HTTP 层，未受限时） | `/api/parse` 1.8s/2.7s 正确返回标题与档位；`/api/more` 9.6s 返回 `原始档 19,027,256B / 1080x1920`；`/api/file` 200 + `video/mp4` + 正确 `content-length`；`/api/img` 200 + `image/jpeg` 43,758B |

### 9.3 新增限制观测：`TICKET_IP_RESTRICTED`（重要）

高频调用后 gate 会返回 **429**：

```json
{"error":"当前请求暂时无法处理，请稍后再试。","message":"当前请求暂时无法处理，请稍后再试。",
 "code":"TICKET_IP_RESTRICTED","reason":"ticket_ip_restricted","securityDialog":true,
 "clientIp":"…","supportCode":"ticket_ip_restricted"}
```

- 触发是**按 IP 的突发/额度限流**：连续快速解析若干次后被拒，冷却十几秒~数分钟可恢复（实测同一 IP 隔 12s 又拿到票据，但连点后再次被拒）
- 这是站方侧的额度，**网页端的"每天 5–10 次"只是前端计数器**，服务端另有 IP 层判定
- WebUI 已把它翻成人话并上冷却倒计时（避免用户白点）；批量/高频场景应改用第 6 节的直连项目（不经过该站）

### 9.4 安全边界

`/api/file` 与 `/api/img` 只代理白名单后缀的源站（`*.douyinvod.com`/`*.douyin.com`/`*.douyinpic.com`/`*.xhscdn.com`/`*.kuaishou.com` 等），拒绝 IP 直连 —— 避免本服务被当成任意 URL 代理（SSRF/开放式代理）。

## 10. 挂到网络上（局域网 / 公网）

### 10.1 三种范围

| 范围 | 怎么起 | 谁能访问 | 需要管理员 | 依赖 |
|---|---|---|---|---|
| 仅本机 | `python hellotik_webui.py`（默认 `127.0.0.1`） | 只有这台机器 | 否 | 无 |
| **局域网** | `python hellotik_webui.py --public` | 同网段设备（手机/别的电脑） | **是，放行防火墙** | 无 |
| **公网** | 上面 + `cloudflared tunnel --url http://127.0.0.1:8765` | 任何拿到 URL+口令的人 | 否（走外连隧道） | 需要 cloudflared |

`--public` 会自动做两件事：监听 `0.0.0.0`，并**强制访问口令**（不给 `--token` 就随机生成，启动时打印）。

一键脚本：`start-public.cmd [端口]` —— 自动生成并复用 `webui_token.txt` 里的口令，起本地服务 + 公网隧道，并把三个地址打出来。关掉两个窗口即停。

### 10.2 访问口令的实现

- 校验点：`Handler._gate()`，`GET`/`POST` 全部经过
- 口令来源：cookie `ht_k` **或** query `?k=`
- 用 `/?k=口令` 打开一次 → 回 `Set-Cookie: ht_k=…; Path=/; Max-Age=2592000; SameSite=Lax`，之后浏览器不用再带 query
  - 这一点是必需的：`<a href="/api/file?...">` 这种下载链接没法附加 query，只能靠 cookie
- 未通过：页面回一个说明页（401），接口回 `{"error":"缺少或错误的口令…"}`（401）
- 附带限流：口令模式下每 IP **120 次/分钟**，超出 429（实测发 130 次，17 次被 429）

### 10.3 实测（本机本轮验证）

| 项 | 结果 |
|---|---|
| 监听 | `0.0.0.0:8765`（`Get-NetTCPConnection` 确认） |
| 本机无口令 | `GET /` → **401**；`GET /api/status` → **401**；`/api/file` → **401**；错口令 → **401** |
| 本机带口令 | `GET /?k=…` → **200**（14581B）+ 下发 cookie `ht_k`；随后不带 query 的 `/api/status` → `ok=true, auth=true` |
| 局域网地址 | `http://192.168.1.10:8765/?k=…` → **200**；不带口令 → **401** |
| 公网隧道 | `https://try-advanced-delicious-massachusetts.trycloudflare.com`（`cf-ray …-LAX`），无口令 **401**、带口令 **200**、`/api/status` 里 `host` 回显公网域名 |
| 公网真实解析 | 经隧道 `POST /api/parse` → **3.1s**，`ok=true`，标题正确，返回 `sid` |
| 限流 | 130 次请求 → **17 次 429**，符合 120/min |

### 10.4 局域网要过防火墙这一关

本机防火墙 Domain/Private/Public 三个 profile 全开、`DefaultInboundAction` 为未配置（即**默认阻止入站**），且没有 8765 的规则；当前进程**不是管理员**，所以规则得由用户执行一次：

```powershell
# 管理员 PowerShell，执行一次即可
New-NetFirewallRule -DisplayName hellotik-WebUI -Direction Inbound -Protocol TCP -LocalPort 8765 -Action Allow
# 撤销
Remove-NetFirewallRule -DisplayName hellotik-WebUI
# 查看
Get-NetFirewallRule -DisplayName hellotik-WebUI | Select DisplayName,Enabled,Direction,Action
```

另外要注意：Windows 在程序首次监听时可能弹「允许访问」对话框，需要**同意**（等同建规则）。所以即使不手敲命令，也得在弹窗上点一下。

**不想碰防火墙**就直接用公网隧道 —— cloudflared 是纯出站连接（QUIC 到 Cloudflare 边缘），不占端口、不需要管理员、不需要路由器端口映射。

### 10.5 公网暴露的安全须知

- **务必带口令**：`--public` 已强制；再加隧道等于全网可达，别用默认无口令模式
- `/api/file` 的代理白名单限制了 SSRF 面（见 9.4），但服务本身仍会**以你的 IP** 去请求 hellotik 上游 —— 也就是说**别人用你的公网地址解析，消耗的是你这台机器的 IP 配额**（`TICKET_IP_RESTRICTED`，见 9.3）。别公开转给一堆人
- quick tunnel 的地址是**随机且临时**的，重启就换；要固定域名就得用 Cloudflare 账号的 named tunnel
- 想收掉公网：关掉 cloudflared 窗口即可（本地/局域网仍可用）

### 10.6 一键启动

```bat
start-public.cmd            :: 端口 8765
start-public.cmd 8080       :: 换端口
```

输出示例（实测）：

```
  hellotik WebUI starting...
  token    : <你的口令>
  local    : http://127.0.0.1:8765/?k=<你的口令>
  LAN      : http://192.168.1.10:8765/?k=<你的口令>
  public   : see the cloudflared window for the https://xxx.trycloudflare.com link
```

> `bin\cloudflared.exe`（cloudflared 2026.11.0，windows-amd64）已下载到项目里；GitHub 直连不通，是用 `ghproxy.net` 镜像取的，下载会分片续传（`curl -C -`）。


---

## 11. 压缩画质（服务端 ffmpeg 重编码）

界面上每个档位行多了个「压缩」按钮，工具栏多了「压缩到 360p/480p/720p/1080p」下拉——原档是站方的高码率 mp4，压缩档是本机用 ffmpeg 重编码出来的小体积版本，适合发微信/存档。

### 11.1 依赖

| 组件 | 位置 | 说明 |
| --- | --- | --- |
| ffmpeg | `bin\ffmpeg\bin\ffmpeg.exe` | 9.0.2-essentials_build（含 libx264），本机原本没有，从 gyan.dev 取的 |
| 缓存 | `cache\<key>.mp4` | 同一视频 + 同一目标高度只编码一次，再点直接秒回 |

服务端启动时会探测：`shutil.which("ffmpeg")` → `bin\ffmpeg.exe` → 遍历 `bin\*\`。找不到就把按钮置灰并提示「服务端未安装 ffmpeg」，功能整体降级但不影响下载原档。

### 11.2 编码参数（`COMPRESS_PRESETS`）

| 目标高度 | CRF | 音频 | 用途 |
| --- | --- | --- | --- |
| 1080 | 24 | 128k | 基本保留画质 |
| 720 | 27 | 96k | 默认，体积/画质平衡 |
| 480 | 29 | 64k | 聊天转发 |
| 360 | 31 | 48k | 最小 |

命令：`ffmpeg -user_agent <UA> -i <代理直链> -vf scale=-2:H -c:v libx264 -preset veryfast -crf N -profile:v high -pix_fmt yuv420p -c:a aac -b:a ABR -ac 2 -movflags +faststart -f mp4 out.mp4`

几个刻意的选择：

- **缩放只给高度**（`scale=-2:720`）：竖屏视频宽度按比例自动算（1080x1920 → 406x720），`-2` 保证宽是偶数（H.264 要求）。
- **走站内代理直链再喂给 ffmpeg**：源 CDN 有 Referer 防盗链，直连会 403；代理链接不需要 Referer。
- **`-movflags +faststart`**：moov 挪到文件头，边下边播、方便网页预览。
- **并发上限 2**（`threading.Semaphore(2)`）：ffmpeg 吃满多核，不做限制的话两个请求就能把机器打满，连带解析接口一起卡。

### 11.3 接口

| 方法 | 路径 | 输入 | 输出 |
| --- | --- | --- | --- |
| POST | `/api/compress` | `{src, name, height, orig, vid}` | `{ok, key, size, height, name, cached, secs, orig}` |
| GET | `/api/cfile` | `?key=<16位hex>&name=` | 压缩后的 mp4（`attachment`） |
| GET | `/api/status` | — | 新增 `ffmpeg`、`presets`、`cached` 三个字段 |

缓存键 = `sha1(vid|height|orig_size)`。`vid` 由前端传「分享链接|标题」——**不能拿 `src` 当键**：抖音 CDN 直链每次解析都换签名，拿 src 做键会 100% miss（实测第二轮仍是 `cached:false`）。改成稳定身份后第二轮 `cached:true, 0s`。

### 11.4 实测

服务端（真接口，v.douyin.com/L4NpDJ6/，源 1.45 MB 档）：

| 目标 | 产物 | 体积 | 耗时 | 缓存 |
| --- | --- | --- | --- | --- |
| 720 | 493,459 B | 省 66% | 5.4s | 首发 no / 复点 yes |
| 360 | 134,500 B | 省 91% | 3.4s | 首发 no |

产物探测：`h264 270x480 30fps 10.15s 345 kbps`（源是 720p 档）。

浏览器（CDP 无头 Chrome，走完整 UI）：阶段一 1.5s 出 2 行 → 阶段二 10.1s 补到 4 行（原始档 18.1 MB 1080x1920）→ 点第 1 行「压缩」（720p）：

```
压缩档 720p  1.12 MB  省 94%  原 18.1 MB  12.8s  下载压缩档  （重编码，非站内原档）
```

产物探测：`h264 406x720 10.13s 927 kbps 1,174,268 B`。下载链 `href=/api/cfile?key=30ec75fb560bdb76&name=…_1080x1920_压缩720.mp4`。

### 11.5 注意

- 压缩档是**本机重编码**，不是站方原档：体积小很多，但画质与原始档不可比（尤其 360p）。要收藏就用原档。
- 编码在主进程里跑（子进程 ffmpeg），单条 720p 原始档约 13s、1.45MB 档约 5s；同时点多个会排队（并发 2）。
- 缓存落在 `cache\`，删掉即可重编；`/api/status` 的 `cached` 字段是当前缓存文件数。

---

## 12. X（推特）支持（v1.2 新增）

### 12.1 为什么不能直接抓

本机实测：`x.com` / `api.x.com` / `api.twitter.com` / `cdn.syndication.twimg.com` / `video.twimg.com` / `pbs.twimg.com` **全部超时**（12s 以上，且不是 403，是被网络层挡住）。注册表里留着 `ProxyServer=127.0.0.1:7890` 但 `ProxyEnable=0`，即装过代理、当前没开；常见代理端口均无监听。

后果：`yt-dlp -J` 对所有测试推文都拿不到元数据（报 `api.x.com timed out` / `WinError 10061`）。所以「直接调 X 官方接口」这条路在本机走不通，除非用户先把代理打开。

### 12.2 走通的链路：x2twitter / savetwitter + dl.snapcdn.app

`hellotik.app` 首页只有抖音/小红书/快手（`/zh/twitter`、`/zh/x` 等全部 404），X 需要另一套来源。实测可用：

```
POST https://x2twitter.com/api/ajaxSearch
  header: content-type: application/x-www-form-urlencoded
          x-requested-with: XMLHttpRequest
  body:   q=<推文链接>&lang=en
  -> {"status":"ok","data":"<html>"}
```

返回的 HTML 里，每条媒体一个 `div.tw-video` 块，块内是缩略图 + 若干下载按钮：

```html
<a onclick="showAd()" href="https://dl.snapcdn.app/get?token=<JWT>"
   rel="nofollow" class="tw-button-dl button dl-success">
   <i class="icon icon-download"></i> Download MP4 (1280p)</a>
```

`token` 是 JWT，第二段（base64url）解出来就是真实地址与文件名：

```json
{"url":"https://video.twimg.com/ext_tw_video/<媒体ID>/pu/vid/720x1280/<名>.mp4?tag=12",
 "filename":"X2Twitter.com_<名>_1280p.mp4","nbf":…,"exp":…,"iat":…}
```

`exp - iat = 3600` → **直链有效期 1 小时**。

`https://dl.snapcdn.app/get?token=…` 是 Cloudflare 前置（`server: clo`）的服务端代理：它自己去 `video.twimg.com` 回源，再把文件吐给客户端。实测支持 `Range`（`206 Partial Content` + `Content-Range`）、`Content-Type: video/mp4`、`Content-Disposition: attachment`。**所以本机不需要能连上 X**。

`savetwitter.net` 的 `/api/ajaxSearch` 形状完全一致（同一个 snapcdn 后端），代码里做成互备：x2twitter 失败自动换 savetwitter。

### 12.3 本 WebUI 里的实现

| 环节 | 做法 |
|---|---|
| 平台识别 | `detect()` 认 `x.com / twitter.com / t.co`，正则放在最前（其余平台照旧） |
| 元数据 | 解析 ajaxSearch 的 HTML：`<h3>` 取正文；按 `div.tw-video` 分块，每块一组档位 |
| 分档 | 每块的按钮文案给画质（`1280p/852p/568p`）；真实地址路径里带分辨率 → 直接当"分辨率"列，已与 ffprobe 实测一致。正则用 `/vid/(?:[a-z0-9]+/)?(\d+x\d+)/`：`amplify_video` 类推文路径形如 `/vid/avc1/728x720/`，中间多一层编码目录 |
| 多视频推文 | 按真实地址里的媒体 ID（`/ext_tw_video/<ID>/`）归组；一条推文多个视频时标签写 `1280p（视频 1）` |
| 作者/时长 | 尽力调 `api.fxtwitter.com/i/status/<id>`（本机可达），按媒体 ID 回填作者名与每条视频时长；失败不影响解析 |
| 封面 | `pbs.twimg.com` 不可达 → 用同一媒体的 snapcdn 图片直链（`Download Photo` 那条）当封面，仍走 `/api/img` |
| 体积 | 对每条 snapcdn 直链探 `Content-Length`（拿不到就退化为 `Range: bytes=0-0` 读 `Content-Range`），并发 8 路 |
| 下载 | `dl.snapcdn.app` 加进 `ALLOW_SUFFIX`，并且**不再过 hellotik 换链**（`direct_src()` 判定，它本身就是代理） |
| 压缩 | 同一个 ffmpeg 链路，输入直接用 snapcdn 直链（无需 Referer） |
| 阶段 | X 各档位在阶段一一次取全 → 返回 `complete: true`、`moreAvailable: false`，前端不再发 `/api/more`，直接高亮最佳档 |

前端：平台徽章加 `X（推特）`；档位表体积列后面追时长（`15.6 MB · 113s`）；结果卡加一行「直链时效：约 N 分钟后过期」；提示文案按平台切换。

### 12.4 实测

| 输入 | 结果 |
|---|---|
| `x.com/CTVJLaidlaw/status/1600649710662213632`（2 个视频） | 2.5s 返回 6 档：1280p(16.3MB/14.9MB)、852p、568p，分辨率 720x1280 / 480x852 / 320x568，时长 113s / 102s，best=1280p（视频1） |
| `x.com/historyinmemes/status/1790637656616943991`（单视频，`amplify_video` 路径） | 2.4s 返回 3 档：720p(1.40MB, 728x720)、360p(553KB, 364x360)、270p(197KB, 272x270)，时长 15.5s |
| 下载（`/api/file`） | 568p 那条 3,668,142 B / 1.7s，`h264 320x568 duration=102.2s` |
| 封面（`/api/img`） | 200 image/jpeg 164,993 B（浏览器里 `naturalWidth=728`，确实渲染出来） |
| 压缩（`/api/compress` 360p） | 3.67MB → 1.31MB，4.3s，`h264 202x360` |
| 无视频/已删除的推文 | `X 解析失败：这条推文没有可下载的视频（可能已删除、私密，或本身不含视频）` |
| 浏览器全链路（无头 Chrome + CDP） | 徽章 `识别为：X（推特）`；3s 出 6 行档位、时长与分辨率齐全、最佳档高亮；按钮 下载/复制直链/压缩 都在 |

### 12.5 注意与边界

- **第三方依赖**：解析与文件都依赖 x2twitter / savetwitter / snapcdn 这三个第三方站点；它们改接口、加广告页或挂掉，X 这条路就断（抖音那套仍可用）。代码里已做双站互备，但两者同一个后端，属"单点"。
- **直链 1 小时过期**：`dl.snapcdn.app` 的 token 有效期 1 小时，过期重新解析即可；「下载」按钮是当场流的，不受影响。
- **代理方案仍在**：`bin\yt-dlp.exe`（2026.10.26）已备好。用户把代理打开（注册表里那台 `127.0.0.1:7890`）后，`yt-dlp` 直连 X 是更稳的正路：`yt-dlp --proxy http://127.0.0.1:7890 -f bv*+ba -o "%(id)s.%(ext)s" <推文链接>`。
- **只处理视频**：目前一条推文多视频会给多行档位（按"视频 N"标号），不做合并、不抓图片批量（图片档位被当作封面来源用掉）。
