// 用 CDP 驱动无头 Chrome 真实验证 WebUI：填链接 → 点解析 → 等到两阶段渲染完成
const CDP = process.argv[2] || 'http://127.0.0.1:9223';
const PAGE = process.argv[3] || 'http://127.0.0.1:8765/';
const SHARE = process.argv[4] || 'https://v.douyin.com/L4NpDJ6/';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function targets() {
  const r = await fetch(CDP + '/json/list');
  return await r.json();
}

class WS {
  constructor(url) {
    this.url = url; this.id = 0; this.pending = new Map();
  }
  open() {
    return new Promise((res, rej) => {
      this.ws = new WebSocket(this.url);
      this.ws.onopen = () => res();
      this.ws.onerror = (e) => rej(new Error('ws error ' + (e.message || '')));
      this.ws.onmessage = (ev) => {
        let m; try { m = JSON.parse(ev.data); } catch { return; }
        if (m.id && this.pending.has(m.id)) {
          const { res, rej } = this.pending.get(m.id);
          this.pending.delete(m.id);
          m.error ? rej(new Error(JSON.stringify(m.error))) : res(m.result);
        }
      };
    });
  }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((res, rej) => {
      this.pending.set(id, { res, rej });
      this.ws.send(JSON.stringify({ id, method, params }));
      setTimeout(() => { if (this.pending.has(id)) { this.pending.delete(id); rej(new Error('timeout ' + method)); } }, 180000);
    });
  }
}

const EXPR = `(async () => {
  const $ = (id) => document.getElementById(id);
  const t0 = Date.now();
  $('url').value = ${JSON.stringify(SHARE)};
  $('url').dispatchEvent(new Event('input'));
  const badge = $('plat').textContent;
  $('go').click();
  let phase1 = null, phase2 = null, last = null, firstMsg = null, errFrame = null;
  while (Date.now() - t0 < 90000) {
    await new Promise(r => setTimeout(r, 600));
    const rows = [...document.querySelectorAll('#result tbody tr')].map(tr => tr.innerText.replace(/\\s+/g,' ').trim());
    const loading = !!document.querySelector('#result tr.load');
    last = { rows, loading, msg: $('msg').innerText, btn: $('go').innerText,
             btnDisabled: $('go').disabled, elapsed: +((Date.now()-t0)/1000).toFixed(1) };
    if (!firstMsg && last.msg) firstMsg = JSON.parse(JSON.stringify(last));
    if (!errFrame && /解析失败/.test(last.msg)) errFrame = JSON.parse(JSON.stringify(last));
    if (!phase1 && rows.length) phase1 = JSON.parse(JSON.stringify(last));
    if (!loading && rows.length >= 3) { phase2 = last; break; }
    if (errFrame && Date.now() - t0 > 4000) break;
  }
  const img = document.querySelector('#result img.cover');
  return JSON.stringify({
    badge,
    title: document.querySelector('#result .title') ? document.querySelector('#result .title').innerText : null,
    coverLoaded: !!(img && img.naturalWidth),
    phase1, firstMsg, errFrame, phase2: phase2 || last,
    buttons: [...document.querySelectorAll('#result tbody tr:first-child button')].map(b => b.textContent),
    footer: $('origin').textContent
  }, null, 1);
})()`;

(async () => {
  const list = await targets();
  const page = list.find((t) => t.type === 'page');
  if (!page) throw new Error('no page target: ' + JSON.stringify(list));
  console.log('target:', page.id, page.url);
  const ws = new WS(page.webSocketDebuggerUrl);
  await ws.open();
  await ws.send('Page.enable');
  await ws.send('Runtime.enable');
  await ws.send('Page.navigate', { url: PAGE });
  await sleep(2500);
  const r = await ws.send('Runtime.evaluate', { expression: EXPR, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) console.log('PAGE EXCEPTION:', JSON.stringify(r.exceptionDetails.exception));
  console.log('--- WebUI 实测 ---');
  console.log(r.result.value);
  ws.ws.close();
})().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
