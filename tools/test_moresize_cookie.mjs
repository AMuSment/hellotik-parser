// 完整 + 带 parse_sid 会话 cookie 的 more-size 验证
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
const jar = new Map();
const cookieHdr = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
async function post(url, body, extra = {}) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: '*/*', origin: BASE, referer: `${BASE}/zh/douyin`, 'user-agent': UA, ...(jar.size ? { cookie: cookieHdr() } : {}), ...extra },
    body: JSON.stringify(body),
  });
  for (const sc of r.headers.getSetCookie?.() ?? []) {
    const [kv] = sc.split(';'); const i = kv.indexOf('=');
    jar.set(kv.slice(0, i).trim(), kv.slice(i + 1).trim());
  }
  const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch { j = { raw: t.slice(0, 300) }; }
  return { httpStatus: r.status, json: j };
}
const target = process.argv[2] || 'https://v.douyin.com/L4NpDJ6/';
const uwx = 'uwx_' + String(Date.now()).slice(-6) + 'sdAA';

const g = await post(`${BASE}/api/gate-e5eea8`, { requestURL: target, isBatch: false, mode: 'single' });
console.log('GATE:', g.httpStatus, 'cookie jar =', JSON.stringify([...jar]));
const ticket = g.json.tk_e5eea8, seed = g.json.sd_e5eea8;
const key = crypto.createHash('sha256').update(`${ticket}:${seed}`).digest();
const iv = crypto.randomBytes(12);
const c = crypto.createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify({ requestURL: target, isBatch: false, parseMode: 'single', isMobile: 'false', isoCode: 'CN', adType: 'adsense', uwx_id: uwx, pagePath: '/zh/douyin', externalRequestId: crypto.randomUUID(), qualityTier: 'hd' }))), c.final(), c.getAuthTag()]);
const p = await post(`${BASE}/api/parse`, { tk_e5eea8: ticket, pl_e5eea8: ct.toString('base64'), iv_e5eea8: iv.toString('base64'), vr_e5eea8: 1 });
const raw = p.json;
const c2 = Buffer.from(deob(raw.data), 'base64'), iv2 = Buffer.from(deob(raw.key), 'base64');
const d = crypto.createDecipheriv('aes-256-cbc', Buffer.from(SALT, 'utf8'), iv2);
const payload = JSON.parse(Buffer.concat([d.update(c2), d.final()]).toString('utf8'));
const token = payload.moreSizeToken;
const tp = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
const sid = jar.get('parse_sid');
console.log('parse=', p.httpStatus, 'status=', raw.status, 'title=', payload.title, 'tiers=', payload.videos?.[0]?.video_fullinfo?.map((v) => v.type));
console.log('token payload =', JSON.stringify(tp));
console.log('sha256(parse_sid) b64url =', sid ? b64u(crypto.createHash('sha256').update(sid, 'utf8').digest()) : '(no sid)');
console.log('subjectHash match parse_sid?', sid ? tp.subjectHash === b64u(crypto.createHash('sha256').update(sid, 'utf8').digest()) : false);
console.log('sha256(uwx) match?', tp.subjectHash === b64u(crypto.createHash('sha256').update(uwx, 'utf8').digest()));

const ms = await post(`${BASE}/api/more-size`, { input: target }, { 'X-More-Size-Token': token });
console.log('\nMORE_SIZE ->', ms.httpStatus, JSON.stringify(ms.json).slice(0, 200));
if (ms.json?.encrypt) {
  const a = Buffer.from(deob(ms.json.data), 'base64'), b = Buffer.from(deob(ms.json.iv), 'base64');
  const k = crypto.createHash('sha256').update(token, 'utf8').digest();
  const dd = crypto.createDecipheriv('aes-256-cbc', k, b);
  const out = JSON.parse(Buffer.concat([dd.update(a), dd.final()]).toString('utf8'));
  console.log('DECODED more-size:', JSON.stringify(out, null, 1).slice(0, 2500));
}
