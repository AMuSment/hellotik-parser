// 追加验证: more-size（超高码率）+ 代理直链下载 + 小红书路径
import crypto from 'node:crypto';
import fs from 'node:fs';

const BASE = 'https://www.hellotik.app';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const mod = await import('./hellotik_parse.mjs').catch(() => null); // 不作为模块用，直接内联
const CUSTOM = 'ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw9876543210-_';
const STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const latin1 = (b) => Buffer.from(b).toString('latin1');
const xk = (s, k = 90) => [...s].map((c) => String.fromCharCode(c.charCodeAt(0) ^ k)).join('');
const rev8 = (s, n = 8) => { let o = ''; for (let i = 0; i < s.length; i += n) o += s.slice(i, i + n).split('').reverse().join(''); return o; };
const unsh = (s) => [...s].map((c) => { const i = CUSTOM.indexOf(c); return i === -1 ? c : STD[i]; }).join('');
const deob = (b) => unsh(rev8(xk(latin1(Buffer.from(b, 'base64')))));

const H = (e = {}) => ({ 'content-type': 'application/json', accept: '*/*', origin: BASE, referer: `${BASE}/zh/douyin`, 'user-agent': UA, ...e });
async function post(url, body, extra) {
  const r = await fetch(url, { method: 'POST', headers: H(extra), body: JSON.stringify(body) });
  const t = await r.text();
  let j = null; try { j = JSON.parse(t); } catch { j = { raw: t.slice(0, 400) }; }
  return { httpStatus: r.status, json: j };
}

// ---- 1) 复用 parse 链路（这里直接内联，避免 CLI 副作用）----
const PROFILE = { authRoute: 'gate-e5eea8', tk: 'tk_e5eea8', seed: 'sd_e5eea8', fKey: 'tk_e5eea8', fPayload: 'pl_e5eea8', fIv: 'iv_e5eea8', fVer: 'vr_e5eea8' };
const SALT = '93838338562359368888868323563256';

async function fullParse(url, uwxId, pagePath = '/zh/douyin') {
  const g = await post(`${BASE}/api/${PROFILE.authRoute}`, { requestURL: url, isBatch: false, mode: 'single' });
  const ticket = g.json[PROFILE.tk], seed = g.json[PROFILE.seed];
  const key = crypto.createHash('sha256').update(`${ticket}:${seed}`).digest();
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plain = { requestURL: url, isBatch: false, parseMode: 'single', isMobile: 'false', isoCode: 'CN', adType: 'adsense', uwx_id: uwxId, pagePath, externalRequestId: crypto.randomUUID(), qualityTier: 'hd' };
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(plain))), c.final(), c.getAuthTag()]);
  const p = await post(`${BASE}/api/parse`, { [PROFILE.fKey]: ticket, [PROFILE.fPayload]: ct.toString('base64'), [PROFILE.fIv]: iv.toString('base64'), [PROFILE.fVer]: 1 });
  const raw = p.json;
  let payload = null;
  if (raw.encrypt) {
    const c2 = Buffer.from(deob(raw.data), 'base64');
    const iv2 = Buffer.from(deob(raw.key), 'base64');
    const d = crypto.createDecipheriv('aes-256-cbc', Buffer.from(SALT, 'utf8'), iv2);
    payload = JSON.parse(Buffer.concat([d.update(c2), d.final()]).toString('utf8'));
  }
  return { gate: g.httpStatus, parse: p.httpStatus, raw, payload };
}

const target = process.argv[2] || 'https://v.douyin.com/L4NpDJ6/';
const r = await fullParse(target, 'uwx_' + String(Date.now()).slice(-6) + 'zzAA');
console.log('PARSE:', r.parse, 'title=', r.payload?.title, 'type=', r.payload?.type);
const token = r.payload?.moreSizeToken;
console.log('moreSizeToken:', token ? token.slice(0, 60) + '...' : null);

// ---- 2) more-size 探测（试几种 input 语义）----
for (const input of [target, r.payload?.url, token]) {
  try {
    const ms = await post(`${BASE}/api/more-size`, { input }, { 'X-More-Size-Token': token });
    let dec = null, err = null;
    if (ms.json?.encrypt && ms.json.data && ms.json.iv) {
      try {
        const ct = Buffer.from(deob(ms.json.data), 'base64');
        const iv = Buffer.from(deob(ms.json.iv), 'base64');
        const k = crypto.createHash('sha256').update(token, 'utf8').digest();
        const d = crypto.createDecipheriv('aes-256-cbc', k, iv);
        dec = JSON.parse(Buffer.concat([d.update(ct), d.final()]).toString('utf8'));
      } catch (e) { err = e.message; }
    }
    console.log('MORE_SIZE input=' + String(input).slice(0, 40), '->', ms.httpStatus, JSON.stringify(ms.json).slice(0, 200), err ? 'DEC_ERR=' + err : '', dec ? 'DEC=' + JSON.stringify(dec).slice(0, 800) : '');
  } catch (e) { console.log('MORE_SIZE_ERR', e.message); }
}

// ---- 3) 代理直链 + 真实下载 ----
const direct = r.payload?.videos?.[0]?.url || r.payload?.url;
const px = await post(`${BASE}/api/download-proxy-url`, { url: direct, sourceUrl: direct, type: 'video' });
const proxy = px.json?.url;
console.log('PROXY:', proxy ? proxy.slice(0, 120) + '...' : JSON.stringify(px).slice(0, 200));
if (proxy) {
  const dl = await fetch(proxy, { headers: { 'user-agent': UA, referer: `${BASE}/zh/douyin` } });
  const buf = Buffer.from(await dl.arrayBuffer());
  fs.mkdirSync('dl', { recursive: true });
  fs.writeFileSync('dl/proxy_test.mp4', buf);
  console.log('PROXY_DOWNLOAD:', dl.status, buf.length, 'bytes ->', 'dl/proxy_test.mp4', 'magic=', buf.slice(4, 12).toString('hex'));
}
const dl2 = await fetch(direct, { headers: { 'user-agent': UA, referer: `${BASE}/zh/douyin` } });
const buf2 = Buffer.from(await dl2.arrayBuffer());
fs.mkdirSync('dl', { recursive: true });
fs.writeFileSync('dl/direct_test.mp4', buf2);
console.log('DIRECT_DOWNLOAD:', dl2.status, buf2.length, 'bytes magic=', buf2.slice(4, 12).toString('hex'));
