#!/usr/bin/env node
/**
 * hellotik.app 抖音/小红书 无水印解析下载 — 协议复现（研究用）
 *
 * 逆向自站点 JS chunk：
 *   chunk 2716 / module 62261  -> generateOutput(data,key,salt)  解析响应解密
 *   chunk 951  / module 60951  -> decryptMoreSizeResponse(data,iv,token)  更高码率响应解密
 *   chunk 4968                 -> /api/more-size 前端调用语义（input=原始分享串, X-More-Size-Token=moreSizeToken）
 *   chunk 7630                 -> uwx 设备指纹
 *
 * 链路：
 *   1. POST /api/gate-e5eea8                {requestURL,isBatch,mode}          -> tk/sd/ex + Set-Cookie parse_sid
 *   2. AES-256-GCM(key=SHA256(`tk:sd`))     body {tk,pl,iv,vr}                 -> POST /api/parse
 *   3. 响应 {status:0,encrypt:true,data,key} -> generateOutput() -> {title,url,videos[],cover,moreSizeToken}
 *   4. POST /api/more-size (X-More-Size-Token) -> decryptMoreSizeResponse()     -> 更高码率 variants
 *   5. POST /api/download-proxy-url         {url}                              -> data.hellotik.app 代理直链
 *   6. 下载（源直链 403 防盗链，必须走代理）
 *
 * 用法:
 *   node hellotik_dl.mjs <分享链接> [--more-size] [--download] [--json]
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const BASE = 'https://www.hellotik.app';
const SALT = '93838338562359368888868323563256';           // chunk 2261 硬编码
const CUSTOM_ALPHABET = 'ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw9876543210-_';
const STD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

// ---------- 变换链 ----------
const latin1 = (b) => Buffer.from(b).toString('latin1');
const xor90 = (s) => [...s].map((c) => String.fromCharCode(c.charCodeAt(0) ^ 90)).join('');
const rev8 = (s, n = 8) => { let o = ''; for (let i = 0; i < s.length; i += n) o += s.slice(i, i + n).split('').reverse().join(''); return o; };
const unshuffle = (s) => [...s].map((c) => { const i = CUSTOM_ALPHABET.indexOf(c); return i === -1 ? c : STD_ALPHABET[i]; }).join('');

/** /api/parse 的 encrypt 响应：先 base64 解码，再 XOR-90 -> 8 字节块反转 -> 字母表还原 */
const deobParse = (b64str) => unshuffle(rev8(xor90(latin1(Buffer.from(b64str, 'base64')))));
/** /api/more-size 的 encrypt 响应：直接对 JSON 字符串做 XOR-90 -> 8 字节块反转 -> 字母表还原 */
const deobMoreSize = (str) => unshuffle(rev8(xor90(str)));

function aesCbcDecrypt(key, iv, ct) {
  const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([d.update(ct), d.final()]);
}
/** chunk 2261 */
export function generateOutput(data, key, salt = SALT) {
  return JSON.parse(aesCbcDecrypt(Buffer.from(salt, 'utf8'), Buffer.from(deobParse(key), 'base64'), Buffer.from(deobParse(data), 'base64')).toString('utf8'));
}
/** chunk 951 */
export function decryptMoreSizeResponse(data, iv, token) {
  const key = crypto.createHash('sha256').update(token, 'utf8').digest();
  return JSON.parse(aesCbcDecrypt(key, Buffer.from(deobMoreSize(iv), 'base64'), Buffer.from(deobMoreSize(data), 'base64')).toString('utf8'));
}

// ---------- 会话 ----------
// 平台由 Referer 决定（前端 rednote 页与 douyin 页构造的请求体完全一致）
let siteReferer = `${BASE}/zh/douyin`;
const jar = new Map();
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
function absorbCookies(res) {
  for (const sc of res.headers.getSetCookie?.() ?? []) {
    const [kv] = sc.split(';'); const i = kv.indexOf('=');
    if (i > 0) jar.set(kv.slice(0, i).trim(), kv.slice(i + 1).trim());
  }
}
async function http(url, { method = 'GET', body, headers = {}, redirect = 'manual' } = {}) {
  const res = await fetch(url, {
    method, redirect,
    headers: { accept: '*/*', 'accept-language': 'zh-CN,zh;q=0.9', origin: BASE, referer: siteReferer, 'user-agent': UA, ...(jar.size ? { cookie: cookieHeader() } : {}), ...(body ? { 'content-type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  absorbCookies(res);
  return res;
}
const jsonOr = async (res) => { const t = await res.text(); try { return JSON.parse(t); } catch { return { raw: t.slice(0, 400) }; } };

// ---------- 协议实现 ----------
/** 取解析票据 + 建立 parse_sid 匿名会话（more-size 的 subject 绑定在这个 cookie 上） */
export async function gate(requestURL, route = 'gate-e5eea8') {
  const res = await http(`${BASE}/api/${route}`, { method: 'POST', body: { requestURL, isBatch: false, mode: 'single' } });
  return { status: res.status, json: await jsonOr(res), sid: jar.get('parse_sid') };
}

/** 解析（AES-256-GCM 加密请求体，返回已解密的明文载荷） */
export async function parse(requestURL, { route = 'gate-e5eea8', uwxId, pagePath = '/zh/douyin', qualityTier = 'hd', isMobile = false } = {}) {
  siteReferer = `${BASE}${pagePath}`;
  const g = await gate(requestURL, route);
  const ticket = g.json.tk_e5eea8 ?? g.json.tk_4a160a;
  const seed = g.json.sd_e5eea8 ?? g.json.sd_4a160a;
  if (!ticket) return { ok: false, stage: 'gate', gate: g };
  const f = ticket.includes('4a160a') ? { k: 'tk_4a160a', p: 'pl_4a160a', i: 'iv_4a160a', v: 'vr_4a160a' } : { k: 'tk_e5eea8', p: 'pl_e5eea8', i: 'iv_e5eea8', v: 'vr_e5eea8' };
  const key = crypto.createHash('sha256').update(`${ticket}:${seed}`).digest();
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plain = {
    requestURL, isBatch: false, parseMode: 'single', isMobile: isMobile ? 'true' : 'false',
    isoCode: 'CN', adType: 'adsense', uwx_id: uwxId, pagePath,
    externalRequestId: crypto.randomUUID(), qualityTier,
  };
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(plain), 'utf8')), c.final(), c.getAuthTag()]);
  const res = await http(`${BASE}/api/parse`, { method: 'POST', body: { [f.k]: ticket, [f.p]: ct.toString('base64'), [f.i]: iv.toString('base64'), [f.v]: 1 } });
  const raw = await jsonOr(res);
  if (!raw?.encrypt) return { ok: false, stage: 'parse', httpStatus: res.status, raw };
  return { ok: true, httpStatus: res.status, qualityTier: raw.qualityTier, payload: generateOutput(raw.data, raw.key), raw };
}

/** 更高码率（1080p 等）：input 必须与解析时的原始字符串逐字节相同 */
export async function moreSize(input, token) {
  const res = await http(`${BASE}/api/more-size`, { method: 'POST', body: { input }, headers: { 'X-More-Size-Token': token } });
  const raw = await jsonOr(res);
  if (!raw?.encrypt) return { ok: false, httpStatus: res.status, raw };
  return { ok: true, httpStatus: res.status, data: decryptMoreSizeResponse(raw.data, raw.iv, token) };
}

/** 站内代理直链（源站 CDN 有 referer 防盗链，直连 403） */
export async function proxyUrl(sourceUrl, type = 'video') {
  const res = await http(`${BASE}/api/download-proxy-url`, { method: 'POST', body: { url: sourceUrl, sourceUrl, type } });
  const j = await jsonOr(res);
  return { status: res.status, url: j?.url, raw: j };
}
export async function uwxId() {
  const res = await http(`${BASE}/account/api/uwx/generate-id`, { method: 'POST', body: {} });
  const j = await jsonOr(res);
  return j?.success && j.data?.uwx_id ? j.data.uwx_id : 'uwx_' + String(Date.now()).slice(-6) + Math.random().toString(36).slice(2, 6) + 'AA';
}

const brOf = (u) => Number(new URL(u).searchParams.get('br') || 0);
const qsOf = (u) => new URL(u).searchParams.get('qs') || '?';
async function measure(url, referer) {
  const res = await fetch(url, { redirect: 'follow', headers: { 'user-agent': UA, referer } });
  const hdrLen = Number(res.headers.get('content-length') || 0);
  const buf = hdrLen && hdrLen < 80 * 1024 * 1024 ? Buffer.from(await res.arrayBuffer()) : Buffer.alloc(0);
  let dim = null;
  // 遍历全部 tkhd box，取宽高非零的那条（音轨 tkhd 宽高为 0）
  // 载荷布局: version+flags(4) | v0:20 / v1:32 | reserved(8) | layer+alt+vol+resv(8) | matrix(36)
  // 盒体为 [4B size][4B 'tkhd'][载荷]，故载荷起点 = 类型串位置 +4
  // -> v0 宽@i+80 高@+84；v1 宽@+92 高@+96（16.16 定点）
  for (let off = 0; ;) {
    const i = buf.indexOf(Buffer.from('tkhd'), off);
    if (i < 0 || buf.length < i + 100) break;
    off = i + 4;
    const base = i + (buf[i + 4] === 1 ? 92 : 80);
    const w = buf.readUInt32BE(base) / 65536, h = buf.readUInt32BE(base + 4) / 65536;
    if (w > 0 && h > 0) { dim = `${w}x${h}`; break; }
  }
  return { status: res.status, finalUrl: res.url, bytes: buf.length || hdrLen, dim, magic: buf.slice(4, 12).toString('ascii') };
}

// ---------- CLI ----------
const isMain = process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]));
if (isMain) {
  const input = process.argv[2];
  if (!input) { console.error('usage: node hellotik_dl.mjs <share_url> [--more-size] [--download] [--json]'); process.exit(2); }
  const wantMore = process.argv.includes('--more-size');
  const wantDl = process.argv.includes('--download');
  const asJson = process.argv.includes('--json');
  const platform = /xiaohongshu|xhslink/i.test(input) ? 'rednote' : 'douyin';
  const pagePath = `/${platform === 'rednote' ? 'zh/rednote' : 'zh/douyin'}`;
  const dev = await uwxId();
  const r = await parse(input, { uwxId: dev, pagePath });
  if (!r.ok) { console.log('FAILED:', JSON.stringify(r).slice(0, 800)); process.exit(1); }
  const p = r.payload;
  const out = { input, platform, pagePath, qualityTier: r.qualityTier, title: p.title, type: p.type, source_url: p.url, cover: p.cover, tiers: p.videos?.[0]?.video_fullinfo?.map((v) => `${v.type}(${v.size}B)`) ?? [], moreSizeToken: !!p.moreSizeToken };

  // 候选池：解析直链所有档位（源码已给出 size） + more-size 变体（更高码率）
  const pool = new Map();
  for (const v of p.videos?.[0]?.video_fullinfo || []) pool.set(v.url, { url: v.url, knownSize: v.size, label: v.type, br: brOf(v.url), qs: qsOf(v.url) });
  if (p.videos?.[0]?.url) pool.set(p.videos[0].url, { url: p.videos[0].url, br: brOf(p.videos[0].url), qs: qsOf(p.videos[0].url) });
  if (wantMore && p.moreSizeToken) {
    const ms = await moreSize(input, p.moreSizeToken);
    if (ms.ok) {
      const list = [];
      if (ms.data.url) list.push({ url: ms.data.url, redirected: ms.data.redirected });
      for (const v of ms.data.variants || []) list.push(v);
      const uniq = [...new Map(list.filter((v) => v?.url && v.redirected !== false).map((v) => [v.url, v])).values()];
      out.more_size_variants = uniq.length;
      for (const v of uniq) pool.set(v.url, { url: v.url, br: brOf(v.url), qs: qsOf(v.url), source: 'more-size' });
    } else out.more_size_error = ms.raw?.error || ms.httpStatus;
  }
  // 逐个经代理实测（体积 + tkhd 分辨率），取最大
  const measured = [];
  for (const c of [...pool.values()].sort((a, b) => b.br - a.br)) {
    const prox = await proxyUrl(c.url);
    if (!prox.url) continue;
    let m = await measure(prox.url, `${BASE}/zh/douyin`);
    if (m.status !== 200 || m.bytes < 1024) { await new Promise((r) => setTimeout(r, 1200)); m = await measure(prox.url, `${BASE}/zh/douyin`); }
    measured.push({ ...c, proxy: prox.url, bytes: m.bytes, dim: m.dim, status: m.status });
  }
  measured.sort((a, b) => b.bytes - a.bytes);
  out.candidates = measured.map((m) => `br=${m.br}${m.dim ? ' ' + m.dim : ''} ${m.bytes}B${m.source === 'more-size' ? ' [more-size]' : ''}`);
  const best = measured.find((m) => m.status === 200 && m.bytes > 1024) || measured[0];
  if (best) out.best = { br: best.br, dim: best.dim, bytes: best.bytes, label: best.label, source: best.source || 'parse', proxy_status: best.status };
  if (wantDl && best?.proxy) {
    const outDir = path.join(process.cwd(), 'dl');
    fs.mkdirSync(outDir, { recursive: true });
    const safe = String(p.title || 'media').replace(/[\\/:*?"<>|\s]+/g, '_').slice(0, 60);
    const file = path.join(outDir, `${safe}_${best.dim || best.br + 'kbps'}.mp4`);
    const res = await fetch(best.proxy, { redirect: 'follow', headers: { 'user-agent': UA, referer: `${BASE}/zh/douyin` } });
    const buf = Buffer.from(await res.arrayBuffer());
    fs.writeFileSync(file, buf);
    out.saved = { file, bytes: buf.length, magic: buf.slice(4, 12).toString('ascii') };
  }
  console.log(asJson ? JSON.stringify(out, null, 2) : JSON.stringify(out, null, 2));
}
