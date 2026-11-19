// hellotik.app 解析协议复现（研究用 · 逆向自站点 JS chunk）
//
// 完整链路:
//   1) POST /api/<gate-route>            -> { tk_*, sd_*, ex_* } 票据
//   2) AES-256-GCM(key=SHA256(`${ticket}:${seed}`), iv=12B random) 加密解析参数
//      POST /api/parse                    -> { status:0, encrypt:true, data, key, qualityTier }
//   3) 响应解密 generateOutput(data,key,SALT)  (来自 chunk 2261 / module 62261)
//        逐字节 XOR 0x5A -> 每 8 字符块反转 -> 自定义字母表还原标准 base64 -> atob -> AES-256-CBC
//        key = utf8("93838338562359368888868323563256")  (32 字节), iv = 同上变换后的 key 字段
//   4) POST /api/download-proxy-url       -> 站内代理直链（绕过 CDN referer 防盗链）
//   5) POST /api/more-size (X-More-Size-Token) -> 更大体积/更高码率
//        解密 decryptMoreSizeResponse(data,iv,token)  (chunk 951 / module 60951)
//        链路同上，但 AES-256-CBC key = SHA256(utf8(token))
//
// 用法:
//   node hellotik_parse.mjs <share_url>              # 解析 + 打印元数据/直链
//   node hellotik_parse.mjs <share_url> --download   # 附带下载媒体到 ./dl
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const BASE = 'https://www.hellotik.app';
const SALT = '93838338562359368888868323563256'; // chunk 2261 硬编码第三参
const CUSTOM_ALPHABET = 'ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw9876543210-_';
const STD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

// ---------- 内嵌 profile（chunk 2716 里 JSON.parse 的配置）----------
const PROFILE = {
  id: '2026w12', authRoute: 'gate-e5eea8',
  tk: 'tk_e5eea8', seed: 'sd_e5eea8', ex: 'ex_e5eea8',
  fKey: 'tk_e5eea8', fPayload: 'pl_e5eea8', fIv: 'iv_e5eea8', fVer: 'vr_e5eea8', fFallback: 'fb_e5eea8',
};
const FALLBACK = {
  id: '2026w03', authRoute: 'gate-4a160a',
  tk: 'tk_4a160a', seed: 'sd_4a160a', ex: 'ex_4a160a',
  fKey: 'tk_4a160a', fPayload: 'pl_4a160a', fIv: 'iv_4a160a', fVer: 'vr_4a160a', fFallback: 'fb_4a160a',
};
const ENC_VERSION = Number(process.env.NEXT_PUBLIC_PARSE_REQUEST_ENCRYPTION_VERSION || '1');
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const b64 = (b) => Buffer.from(b).toString('base64');

// ---------- 响应解码核心 ----------
const latin1 = (buf) => Buffer.from(buf).toString('latin1');

function xorKey(s, k = 90) {
  let out = '';
  for (let i = 0; i < s.length; i++) out += String.fromCharCode(s.charCodeAt(i) ^ k);
  return out;
}
function reverseBlocks(s, n = 8) {
  let out = '';
  for (let i = 0; i < s.length; i += n) out += s.slice(i, i + n).split('').reverse().join('');
  return out;
}
function unshuffleAlphabet(s) {
  let out = '';
  for (const ch of s) {
    const i = CUSTOM_ALPHABET.indexOf(ch);
    out += i === -1 ? ch : STD_ALPHABET[i];
  }
  return out;
}
/** base64 字符串 -> 变换 -> 标准 base64 字符串 */
function deobfuscate(b64str) {
  return unshuffleAlphabet(reverseBlocks(xorKey(latin1(Buffer.from(b64str, 'base64')))));
}

/** chunk 2261 generateOutput: 解 /api/parse 的 encrypt 响应 */
function generateOutput(dataB64, keyB64, salt = SALT) {
  const ct = Buffer.from(deobfuscate(dataB64), 'base64');
  const iv = Buffer.from(deobfuscate(keyB64), 'base64');
  const d = crypto.createDecipheriv('aes-256-cbc', Buffer.from(salt, 'utf8'), iv);
  return JSON.parse(Buffer.concat([d.update(ct), d.final()]).toString('utf8'));
}
/** chunk 951 decryptMoreSizeResponse: 解 /api/more-size 的 encrypt 响应 */
function decryptMoreSize(dataB64, ivB64, token) {
  const ct = Buffer.from(deobfuscate(dataB64), 'base64');
  const iv = Buffer.from(deobfuscate(ivB64), 'base64');
  const key = crypto.createHash('sha256').update(token, 'utf8').digest();
  const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return JSON.parse(Buffer.concat([d.update(ct), d.final()]).toString('utf8'));
}

// ---------- HTTP ----------
function headers(extra = {}) {
  return {
    'content-type': 'application/json', accept: '*/*', 'accept-language': 'zh-CN,zh;q=0.9',
    origin: BASE, referer: `${BASE}/zh/douyin`, 'user-agent': UA, ...extra,
  };
}
async function postJson(url, body, extra) {
  const r = await fetch(url, { method: 'POST', headers: headers(extra), body: JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { json = { raw: text.slice(0, 600) }; }
  return { httpStatus: r.status, json };
}

async function getTicket(targetUrl, profile) {
  const { httpStatus, json } = await postJson(`${BASE}/api/${profile.authRoute}`,
    { requestURL: targetUrl, isBatch: false, mode: 'single' });
  return { httpStatus, ticket: json?.[profile.tk], seed: json?.[profile.seed], expiresAt: json?.[profile.ex], json };
}

function encryptPayload(plain, ticket, seed) {
  const key = crypto.createHash('sha256').update(`${ticket}:${seed}`).digest();
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(plain), 'utf8')), c.final(), c.getAuthTag()]);
  return { payload: b64(ct), iv: b64(iv), v: ENC_VERSION };
}

async function parse(targetUrl, opts = {}) {
  const profile = opts.profile || PROFILE;
  const t = await getTicket(targetUrl, profile);
  if (!t.ticket) return { stage: 'gate', gate: t };
  const plain = {
    requestURL: targetUrl, isBatch: false, parseMode: 'single',
    isMobile: opts.isMobile ? 'true' : 'false',
    isoCode: opts.isoCode || 'CN', adType: 'adsense', uwx_id: opts.uwxId, pagePath: '/zh/douyin',
    externalRequestId: crypto.randomUUID(),
    successCount: '0', totalSuccessCount: '0', firstSuccessDate: null, geoipIp: '',
    qualityTier: opts.qualityTier || 'hd',
    browserQuota: { rewardRequired: false, dailyUsed: 0, dailyLimit: 10, totalSuccessCount: 0 },
    ...(opts.extra || {}),
  };
  const enc = encryptPayload(plain, t.ticket, t.seed);
  const { httpStatus, json } = await postJson(`${BASE}/api/parse`, {
    [profile.fKey]: t.ticket, [profile.fPayload]: enc.payload, [profile.fIv]: enc.iv, [profile.fVer]: enc.v,
  });
  return { stage: 'parse', gate: t, httpStatus, raw: json };
}

async function proxyUrl(sourceUrl, type = 'video') {
  return postJson(`${BASE}/api/download-proxy-url`, { url: sourceUrl, sourceUrl, type });
}
async function moreSize(input, token) {
  return postJson(`${BASE}/api/more-size`, { input }, { 'X-More-Size-Token': token });
}

async function generateUwxId() {
  try {
    const r = await fetch(`${BASE}/account/api/uwx/generate-id`,
      { method: 'POST', headers: { 'content-type': 'application/json', origin: BASE, 'user-agent': UA } });
    const j = await r.json();
    if (j.success && j.data?.uwx_id) return { uwxId: j.data.uwx_id, source: 'server' };
  } catch {}
  return { uwxId: 'uwx_' + String(Date.now()).slice(-6) + Math.random().toString(36).slice(2, 6) + 'AB', source: 'local-fallback' };
}

// ---------- CLI ----------
const target = process.argv[2];
const wantDownload = process.argv.includes('--download');
if (!target) { console.error('usage: node hellotik_parse.mjs <share_url> [--download]'); process.exit(2); }

console.log('TARGET:', target);
const dev = await generateUwxId();
console.log('DEVICE:', JSON.stringify(dev));

const res = await parse(target, { uwxId: dev.uwxId });
if (res.stage === 'gate') {
  console.log('GATE_FAIL:', JSON.stringify(res.gate).slice(0, 800));
  process.exit(1);
}
console.log('GATE:', JSON.stringify({ ok: !!res.gate.ticket, status: res.gate.httpStatus, expiresAt: res.gate.expiresAt }));
const raw = res.raw || {};
console.log('PARSE_META:', JSON.stringify({
  httpStatus: res.httpStatus, status: raw.status, encrypt: raw.encrypt,
  qualityTier: raw.qualityTier, code: raw.code, error: raw.error,
  receipt: raw._ops_parse_receipt, keys: Object.keys(raw),
}));

let payload = null;
if (raw.encrypt && raw.data) {
  try {
    payload = generateOutput(raw.data, raw.key);
    console.log('DECRYPT: OK (generateOutput / AES-256-CBC)');
  } catch (e) {
    console.log('DECRYPT: FAILED ->', e.message);
  }
} else if (raw.data) {
  payload = raw.data;
}

if (payload) {
  const inner = payload.data && typeof payload.data === 'object' ? payload.data : payload;
  console.log('\n===== DECRYPTED PAYLOAD =====');
  console.log(JSON.stringify(inner, null, 2).slice(0, 12000));
  const items = Array.isArray(inner.items) ? inner.items : (inner.video ? [inner] : []);
  const first = items[0] || inner;
  const link = first.video_url || first.url || first.video?.play_addr?.url_list?.[0]
    || first.play_addr?.url_list?.[0] || first.images?.[0]?.url || first.image_url;
  if (link) {
    console.log('\nSOURCE_DIRECT:', String(link).slice(0, 300));
    const px = await proxyUrl(String(link));
    console.log('PROXY_RESULT:', JSON.stringify(px).slice(0, 900));
    const proxied = px.json?.url || px.json?.proxyUrl || px.json?.data?.url;
    if (wantDownload) {
      const outDir = path.join(process.cwd(), 'dl');
      fs.mkdirSync(outDir, { recursive: true });
      const name = (first.title || first.desc || payload.title || 'media').replace(/[\\/:*?"<>|\s]+/g, '_').slice(0, 60);
      const ext = /\.(jpe?g|png|webp|gif)(\?|$)/i.test(String(link)) ? '.jpg' : '.mp4';
      const file = path.join(outDir, name + ext);
      const dl = await fetch(proxied || String(link), { headers: { referer: `${BASE}/zh/douyin`, 'user-agent': UA } });
      const buf = Buffer.from(await dl.arrayBuffer());
      fs.writeFileSync(file, buf);
      console.log('DOWNLOADED:', file, buf.length, 'bytes', 'httpStatus=' + dl.status);
    }
  } else {
    console.log('\n(未在载荷里找到直链字段，字段列表: ' + Object.keys(inner).join(', ') + ')');
  }
}
