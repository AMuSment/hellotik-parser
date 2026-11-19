// 干净单流程: parse -> 立即 more-size（同一 uwx_id、同一 input 字符串）
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
const deob = (b) => unsh(rev8(xk(latin1(Buffer.from(b, 'base64')))));
const b64u = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const H = (e = {}) => ({ 'content-type': 'application/json', accept: '*/*', origin: BASE, referer: `${BASE}/zh/douyin`, 'user-agent': UA, ...e });
async function post(url, body, extra) {
  const r = await fetch(url, { method: 'POST', headers: H(extra), body: JSON.stringify(body) });
  const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch { j = { raw: t.slice(0, 300) }; }
  return { httpStatus: r.status, json: j };
}
const target = process.argv[2] || 'https://v.douyin.com/L4NpDJ6/';
const uwx = 'uwx_' + String(Date.now()).slice(-6) + 'qkAA';
console.log('input      =', JSON.stringify(target));
console.log('sha256(input) b64url =', b64u(crypto.createHash('sha256').update(target, 'utf8').digest()));
console.log('sha256(uwx)   b64url =', b64u(crypto.createHash('sha256').update(uwx, 'utf8').digest()), 'uwx=', uwx);

const g = await post(`${BASE}/api/gate-e5eea8`, { requestURL: target, isBatch: false, mode: 'single' });
const ticket = g.json.tk_e5eea8, seed = g.json.sd_e5eea8;
const key = crypto.createHash('sha256').update(`${ticket}:${seed}`).digest();
const iv = crypto.randomBytes(12);
const c = crypto.createCipheriv('aes-256-gcm', key, iv);
const plain = { requestURL: target, isBatch: false, parseMode: 'single', isMobile: 'false', isoCode: 'CN', adType: 'adsense', uwx_id: uwx, pagePath: '/zh/douyin', externalRequestId: crypto.randomUUID(), qualityTier: 'hd' };
const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(plain))), c.final(), c.getAuthTag()]);
const p = await post(`${BASE}/api/parse`, { tk_e5eea8: ticket, pl_e5eea8: ct.toString('base64'), iv_e5eea8: iv.toString('base64'), vr_e5eea8: 1 });
const raw = p.json;
const c2 = Buffer.from(deob(raw.data), 'base64'), iv2 = Buffer.from(deob(raw.key), 'base64');
const d = crypto.createDecipheriv('aes-256-cbc', Buffer.from(SALT, 'utf8'), iv2);
const payload = JSON.parse(Buffer.concat([d.update(c2), d.final()]).toString('utf8'));
const token = payload.moreSizeToken;
const [h1, body, sig] = token.split('.');
const tpayload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
console.log('\nparse httpStatus=', p.httpStatus, 'status=', raw.status, 'qualityTier=', raw.qualityTier);
console.log('token payload   =', JSON.stringify(tpayload));
console.log('token.inputHash == sha256(input)?', tpayload.inputHash === b64u(crypto.createHash('sha256').update(target, 'utf8').digest()));
console.log('token.subjectHash == sha256(uwx)?', tpayload.subjectHash === b64u(crypto.createHash('sha256').update(uwx, 'utf8').digest()));

for (const cand of [
  { label: 'input=原始字符串', body: { input: target } },
  { label: 'input+extra', body: { input: target, uwx_id: uwx } },
  { label: 'input+key', body: { input: target, key: raw.key } },
]) {
  const ms = await post(`${BASE}/api/more-size`, cand.body, { 'X-More-Size-Token': token });
  let dec = null, err = null;
  if (ms.json?.encrypt && ms.json.data) {
    try {
      const a = Buffer.from(deob(ms.json.data), 'base64'), b = Buffer.from(deob(ms.json.iv), 'base64');
      const k = crypto.createHash('sha256').update(token, 'utf8').digest();
      const dd = crypto.createDecipheriv('aes-256-cbc', k, b);
      dec = JSON.parse(Buffer.concat([dd.update(a), dd.final()]).toString('utf8'));
    } catch (e) { err = e.message; }
  }
  console.log('\nMORE_SIZE', cand.label, '->', ms.httpStatus, JSON.stringify(ms.json).slice(0, 300));
  if (dec) console.log('  DECODED:', JSON.stringify(dec, null, 1).slice(0, 1500));
  if (err) console.log('  DEC_ERR:', err);
}
