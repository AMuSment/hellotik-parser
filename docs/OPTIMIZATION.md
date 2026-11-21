# 优化记录（v2）

这一轮只做**内部质量**：不新增依赖、不改协议、不动文件布局，把「慢、重复请求、边界漏洞」逐条消掉。
所有数字都在同一台机器（Windows / CPython 3.12.14）上用 `tools/bench.py` 复现：

```bash
python tools/bench.py            # 自动拿 git HEAD 的旧实现做对照
python tools/bench.py --old x.py # 指定一份旧实现文件
```

## 1. 结论

| 场景 | 旧实现 | 新实现 | 提速 |
| --- | ---: | ---: | ---: |
| CBC 解密 4KB（单次解析） | 182.75 ms | 8.22 ms | 22.2× |
| CBC 解密 11KB（整档响应） | 506.43 ms | 23.13 ms | 21.9× |
| 混淆链 11KB（XOR+反转+字母表） | 2.87 ms | 0.25 ms | 11.7× |
| more-size 整链解密（11KB） | 549.63 ms | 26.03 ms | 21.1× |
| parse 整链解密（4KB 明文） | 192.00 ms | 11.30 ms | 17.0× |
| GCM 加密 140B（请求体） | 1.99 ms | 0.31 ms | 6.3× |

除了解密，网络侧也少了一半请求：

| 指标 | 旧实现 | 新实现 |
| --- | --- | --- |
| 每档探测请求数 | 3～4（HEAD + 头段 GET + 尾段 GET，分辨率还要再排一次） | 1～2（一次 `Range: bytes=0-65535` 同时拿状态/总体积/分辨率） |
| 探测并发 | 外层 10 线程，内层每档再开一个 2 线程池 | 单层 `min(8, n)` 线程，无嵌套池 |
| 换链请求 | `/api/file`、`/api/compress` 每次命中都重新换 | 300s 进程内缓存 |

## 2. AES：逐比特 GF 乘法 → 字节级查表

旧实现每算一次 `MixColumns` 都跑 8 轮比特循环，4KB 一次 CBC 解密要 180ms 以上，单次解析光解密就够呛。

现在：

- `MixColumns` / `InvMixColumns` 的乘法表（`_M2/_M3/_M9/_M11/_M13/_M14`）进程内建一次，运行期只做 16 次查表 + 异或；
- 轮密钥用整数（`int.from_bytes` 128 位）保存，`AddRoundKey` 一次异或；
- `SubBytes` / `InvSubBytes` 走 `bytes.translate(SBOX_B)`，把 16 次 Python 级查表压成一次 C 调用；
- 轮密钥按 `(key)` 用 `functools.lru_cache` 缓存 —— 同一进程里 SALT 是常量，等于只展开一次。

公开 API 没变（`AES(key).encrypt_block/decrypt_block`、`aes_cbc_decrypt`、`aes_gcm_encrypt`），
另外补了 `aes_cbc_encrypt`（带 PKCS#7）给测试和基准造样本，线上链路不需要加密方向。

正确性由 NIST 向量 + 旧实现逐块比对双重保证（见 `tests/test_core.py`）：

- AES-256 单块：`key=000102…1f`，`pt=00112233445566778899aabbccddeeff` → `ct=8ea2b7ca516745bfeafc49904b496089`；
- 300 个随机块与旧实现 0 差异；
- CBC 在 16 / 64 / 4096 / 16400 字节上与旧实现逐字节一致；
- GCM Test Case 13（全零 key/IV、空明文）→ tag `530f8afbc74536b9a963b4f1c4cb738b`。

## 3. 混淆链：三次逐字符 Python 循环 → 三张 `bytes.translate` 表

`XOR 90`、每 8 字符反转、自定义字母表还原，三步都是定长替换：

- `_T_XOR90`、`_T_ALPHA` 是 256 字节的翻译表，运行期 `bytes.translate()` 一次过；
- 反转按 8 字节切片拼（C 层切片 + join），不再逐字符 `reversed()`；
- 三个 helper（`_xor90/_rev8/_unshuffle`）统一接受 `str` 或 `bytes`，内部走 `latin-1`，调用方不用再关心类型。

顺带修掉一个老坑：旧版对 `str` 做 `b64decode`，遇到 URL 里的 `&amp;`、缺 padding 会抛异常；
新版 `_b64()` 先 `strip()` 再补 `=`，`extract_url()` 末尾也会 `html.unescape()`。

## 4. 网络层

### 4.1 每档一次请求

旧版探规格的流程是：`HEAD` 看长度 → `GET Range: bytes=0-` 找 `moov` → 找不到再 `GET` 尾段，
再加一次分辨率探测；一档 3～4 个请求，页面「追最高画质」时 5 档就是近 20 个请求。

新版 `probe()` 一次 `GET Range: bytes=0-65535` 同时拿到 status / `content-range` 总长 / 头段字节，
`tkhd` 在里面就直接出分辨率；头段没 `moov` 才补一次 `bytes=-262144` 尾段。绝大多数档位 1 个请求搞定。

`total_size()` 统一从 `content-range: bytes 0-65535/19027256` 的「/总数」取体积，拿不到再退回 `content-length`，
所有 header 键先转小写，避免 `Content-Length` / `content-length` 两套键名踩空。

### 4.2 重试与退避

`Session.request()` 对**瞬时失败**重试 2 次（指数退避 0.6→8s）：超时 / 连接重置 / 429 / 5xx。
4xx 里的业务错误（比如 `TICKET_IP_RESTRICTED`）不重试 —— 重试只会把 IP 限流拖得更久。
彻底失败统一返回 `(0, b"")`，上层走同一条失败分支，不再到处 `except: pass`。

### 4.3 下载：流式 + 断点续传

旧版 `urlopen(...).read()` 一次性进内存再写盘，19MB 的原始档在低配上会顶到内存峰值。
新版 `download()`：

- 256KB 分块流式落盘；
- 目标文件已存在就带 `Range: bytes=<已有>-` 续传；
- 服务端忽略 Range（回 200）则从头重下，避免把整文件拼到旧内容后面；
- 本轮零字节进展就停，不空转重试。

## 5. WebUI 服务端

| 问题 | 旧行为 | 现在 |
| --- | --- | --- |
| 断点续传 / 拖动进度条 | `/api/file`、`/api/cfile` 整文件吐，无 `accept-ranges` | 手写 206 + `content-range`，支持 `bytes=a-b` / `bytes=-n`，不可满足的区间回 416 + `bytes */N` |
| 预览 / 探测 | 只实现 GET | 新增 `do_HEAD`，只发头不取体 |
| 401 后连接错位 | 先校验口令再读 body，body 留在 socket 缓冲里，同一条 keep-alive 连接的下一个请求被当成 body | 先 `_read_body()` 再校验；非法/超限直接 `close_connection=True` |
| 超大请求体 | `int(self.headers.get("content-length"))` 裸解析 | `MAX_BODY=64KB`，缺失/非法/超限回 413 |
| 口令比较 | `given != ACCESS_TOKEN`（时序可测） | `hmac.compare_digest()` |
| 会话/缓存泄漏 | `SESSIONS` 只在新会话时清理，`_COMP_DONE` 与 `cache/` 永不过期 | `gc()` 60s 节流：`SESSIONS` 15min、`_COMP_DONE` 6h、超 1h 的 `.part.mp4`、超过 2GiB 的 cache 按 mtime 回收 |
| 换链重复请求 | 每次 `/api/file`、`/api/compress` 都 POST 一次 `/api/download-proxy-url` | 进程内 300s 缓存，超 512 条淘汰最老 128 条 |
| ffmpeg 失败留残片 | 半成品 `.part.mp4` 留在 cache | 校验前 12 字节有 `ftyp` 才认，否则删除 |

平台判定、档位去重/选优、体积解析这些原本在 webui 里抄了一遍的逻辑，现在统一从 `hellotik_dl.py` 导入
（`PLATFORMS` / `detect_platform` / `dedupe_by_size` / `pick_best` / `total_size`），协议改动只需改一处。

## 6. 前端（`webui/index.html`）

- **旧响应不许覆盖新结果**：每次解析新建 `AbortController`，开新解析先 `abort()` 旧的，两次 `fetch` 都带 `signal`；
  回调里用 `alive()` 再校验一次，晚到的 `/api/more` 结果会被直接丢弃。
- **复制直链不再复制 `null`**：第一阶段的档位还没有 `proxy`，现在退回本机代理地址
  `/api/file?u=…&name=…`（同样支持 Range，可粘进播放器或下载器），按钮文案区分「已复制 / 已复制(本机)」。
- **接受分享文案**：粘贴「7.92 复制打开抖音… https://v.douyin.com/xxx/」这类整段文案也能解析，
  服务端 `extract_url()` 负责取出 URL，前端只校验「里面有没有 http(s) 链接」。

## 7. 测试

新增 `tests/`，全部离线（自带假站，不联网）：

```bash
python -m unittest discover -s tests -v
```

- `tests/test_core.py`（13 项）：AES NIST 向量、CBC 往返、GCM tag、parse/more-size 往返、
  `tkhd_dim` 盒解析、`total_size`、`extract_url`（分享文案 / `&amp;` / 无链接）、五平台判定、
  `br_of` / `quality_label`、`dedupe_by_size` / `pick_best`、`pool_from_payload`。
- `tests/test_e2e.py`（8 项）：进程内起一个假 hellotik（gate / parse / more-size / 换链 / 带 Range 的媒体），
  然后跑真实 CLI 与真实 Handler：JSON 解析 + 测量、下载与二次续传、`--no-measure` 不发媒体请求、
  401 不污染 keep-alive、超大 body 413、parse→more、`/api/file` 的 206 与 HEAD、`/api/cfile` 的 `bytes=-100`。
- `tests/test_x.py`（12 项）：固定 yt-dlp `-J` 输出，测档位筛选/去重/体积估算、错误路径、`YTDLP` 与
  `X_PROXY` 的优先级、`--proxy` 是否拼进命令行、`_x_ytdlp_phase` 的返回结构、`.twimg.com` 白名单。

合计 33 项，全部离线（不发任何真实网络请求）。

## 8. X（推特）：yt-dlp 兜底

X 原来只有一条路：`x2twitter.com` / `savetwitter.net` 的 `ajaxSearch` + `dl.snapcdn.app` 服务端代理。
只要它们改接口、被 Cloudflare 拦、或单点挂掉，X 就整段不可用（README 里早写了「有代理时 yt-dlp 更稳」，
但代码没实现）。

这一轮补上兜底，**不替换**原路径（原路径不需要本机能连上 X，仍是默认）：

- `hellotik_dl.py` 新增：
  - `ytdlp_bin()`：`YTDLP` 环境变量 → `PATH` → 仓库 `bin/yt-dlp(.exe)`；
  - `_run_ytdlp(url, timeout=90)`：`yt-dlp -J --no-warnings --no-playlist`，`X_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`
    存在时自动加 `--proxy`，超时/退出码/非 JSON 都归成一行可读错误；
  - `x_formats_to_cands(info)`：丢纯音轨、丢 `m3u8`（同码率重复）、按 `(height, tbr)` 去重、按分辨率与码率降序；
    DASH 分片没有 `filesize` 时用 `tbr × 时长` 估体积；
  - `x_from_ytdlp(url)`：统一成 `{ok, title, author, cover, candidates, best}`；
  - CLI 的 `x` 分支（`_main_x`）：解析 → 打印档位 → `-d` 下载（文件名 `标题_720p.mp4`）。
- `hellotik_webui.py`：`x_phase` 在第三方失败时调用 `H.x_from_ytdlp`，返回体结构与原路径一致，
  只多一个 `"engine": "yt-dlp"`；`/api/status` 增加 `ytdlp` 布尔；`ALLOW_SUFFIX`/`DIRECT_SUFFIX` 增加
  `.twimg.com`，这样兜底出来的直链能直接走 `/api/file`（Range、HEAD 都通）。
- 前端不用改：候选里的 `proxy` 就是直链，`复制直链` 原逻辑已经会优先用它。

注意两点现实约束：`video.twimg.com` 在境内不可达，兜底需要代理（`X_PROXY=...`）；
CLI 的 X 分支**只走** yt-dlp（hellotik 协议本身不服务 X），WebUI 才是「第三方优先、yt-dlp 兜底」。

## 9. 没做的事

- **HTTP keep-alive 连接池**：`urllib` 每次请求新建连接，探测 5 档就是 5 次握手。要再快就得自己写
  `http.client` 连接池，收益（本地 ~50ms/次）不如协议侧改动明显，暂不做。
- **more-size 分批**：站方限流是按 IP 的突发判定，串行反而更安全；当前并发 8 已接近合理上限。
- **ffmpeg 硬件编码**：`-c:v h264_nvenc/qsv` 能再快 3～5 倍，但依赖显卡与驱动，会破坏「开箱即用」，留作可选开关。
- **Node 版（`hellotik_dl.mjs`）本轮未动**：它的 AES 走 `node:crypto` 原生实现，瓶颈在网络上而不在本地计算，
  这一轮的性能改动对它没有意义；`tests/` 与 `tools/bench.py` 也只覆盖 Python 端。
