// more-size 响应解码变体诊断（单次流程内穷举候选变换）
import crypto from 'node:crypto';
const BASE = 'https://www.hellotik.app';
const SALT = '93838338562359368888868323563256';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const CUSTOM = 'ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw9876543210-_';
const STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const latin1 = (b) => Buffer.from(b).toString('latin1');
const xk = (s, k = 90) => [...s].map((c) => String.fromCharCode(c.charCodeAt(0) ^ k)).join('');
const rev8 = (s, n = 8) => { let o = ''; for (let i = 0; i < s.length; i += n) o += s.slice(i, i + n).split('').reverse().join(''); return o; };
const unsh = (s) => [...s].map((c) => { const i = CUSTOM.indexOf(c); return i === -1 ? c : STD[i]; }).join('');
const lookup = (s) => { const p = [...s].map((c) => CUSTOM.indexOf(c)); return { mapped: p.filter((x) => x >= 0).length, unmapped: p.filter((x) => x < 0).length }; };

const jar = new Map();
const cookieHdr = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
async function post(url, body, extra = {}) {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: '*/*', origin: BASE, referer: `${BASE}/zh/douyin`, 'user-agent': UA, ...(jar.size ? { cookie: cookieHdr() } : {}), ...extra }, body: JSON.stringify(body) });
  for (const sc of r.headers.getSetCookie?.() ?? []) { const [kv] = sc.split(';'); const i = kv.indexOf('='); jar.set(kv.slice(0, i).trim(), kv.slice(i + 1).trim()); }
  const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch { j = { raw: t.slice(0, 300) }; }
  return { httpStatus: r.status, json: j, text: t };
}

const target = process.argv[2] || 'https://v.douyin.com/L4NpDJ6/';
const uwx = 'uwx_' + String(Date.now()).slice(-6) + 'vvAA';
const g = await post(`${BASE}/api/gate-e5eea8`, { requestURL: target, isBatch: false, mode: 'single' });
const ticket = g.json.tk_e5eea8, seed = g.json.sd_e5eea8;
const key = crypto.createHash('sha256').update(`${ticket}:${seed}`).digest();
const iv = crypto.randomBytes(12);
const c = crypto.createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify({ requestURL: target, isBatch: false, parseMode: 'single', isMobile: 'false', isoCode: 'CN', adType: 'adsense', uwx_id: uwx, pagePath: '/zh/douyin', externalRequestId: crypto.randomUUID(), qualityTier: 'hd' }))), c.final(), c.getAuthTag()]);
const p = await post(`${BASE}/api/parse`, { tk_e5eea8: ticket, pl_e5eea8: ct.toString('base64'), iv_e5eea8: iv.toString('base64'), vr_e5eea8: 1 });
const raw = p.json;
function deob2261(b64str) { return unsh(rev8(xk(latin1(Buffer.from(b64str, 'base64'))))); }
const c2 = Buffer.from(deob2261(raw.data), 'base64'), iv2 = Buffer.from(deob2261(raw.key), 'base64');
const d = crypto.createDecipheriv('aes-256-cbc', Buffer.from(SALT, 'utf8'), iv2);
const payload = JSON.parse(Buffer.concat([d.update(c2), d.final()]).toString('utf8'));
const token = payload.moreSizeToken;

const ms = await post(`${BASE}/api/more-size`, { input: target }, { 'X-More-Size-Token': token });
console.log('MORE_SIZE:', ms.httpStatus, Object.keys(ms.json));
console.log('RAW data (first 120 chars, JSON-escaped):', JSON.stringify(ms.json.data?.slice(0, 120)));
console.log('RAW iv   :', JSON.stringify(ms.json.iv));
const D = ms.json.data, I = ms.json.iv;
console.log('data len=', D?.length, 'iv len=', I?.length, 'iv lookup=', lookup(I));

const key2 = crypto.createHash('sha256').update(token, 'utf8').digest();
const dec = (ctBuf, ivBuf) => { const dd = crypto.createDecipheriv('aes-256-cbc', key2, ivBuf); return JSON.parse(Buffer.concat([dd.update(ctBuf), dd.final()]).toString('utf8')); };
const b64try = (s) => { try { return Buffer.from(s, 'base64'); } catch { return null; } };

const dataVariants = {
  'xor->rev8->unsh->b64': b64try(unsh(rev8(xk(D)))),
  'xor->rev8->b64': b64try(rev8(xk(D))),
  'xor->b64': b64try(xk(D)),
  'b64->xor->rev8->unsh->b64(2261)': b64try(deob2261(D)),
  'plain b64': b64try(D),
};
const ivVariants = {
  'xor->rev8->unsh->b64': b64try(unsh(rev8(xk(I)))),
  'xor->rev8->b64': b64try(rev8(xk(I))),
  'xor->b64': b64try(xk(I)),
  '2261': b64try(deob2261(I)),
  'plain b64': b64try(I),
};
for (const [dn, db] of Object.entries(dataVariants)) {
  for (const [inm, ib] of Object.entries(ivVariants)) {
    if (!db || !ib || ib.length !== 16) continue;
    try {
      const out = dec(db, ib);
      console.log(`\n*** SUCCESS data=${dn} iv=${inm} ***`);
      console.log(JSON.stringify(out, null, 1).slice(0, 2500));
      process.exit(0);
    } catch (e) { /* keep trying */ }
  }
}
console.log('\n所有组合失败。中间态检查:');
console.log(' XOR ->', JSON.stringify(xk(D).slice(0, 80)));
console.log(' rev8 ->', JSON.stringify(rev8(xk(D)).slice(0, 80)));
console.log(' unsh ->', JSON.stringify(unsh(rev8(xk(D))).slice(0, 80)), 'len=', unsh(rev8(xk(D))).length);
console.log(' iv variants lens:', Object.entries(ivVariants).map(([k, v]) => k + '=' + (v ? v.length : 'null')).join(', '));
