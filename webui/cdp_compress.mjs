// 用 CDP 驱动无头 Chrome 验证「压缩画质」链路：解析 → 点某行「压缩」→ 等 tr.cmp 结果行
// 用法: node webui/cdp_compress.mjs <CDP端点> <页面URL(带?k=)> <分享链接> [目标高度] [行号(0起)]
const CDP = process.argv[2] || 'http://127.0.0.1:9223';
const PAGE = process.argv[3] || 'http://127.0.0.1:8765/';
const SHARE = process.argv[4] || 'https://v.douyin.com/L4NpDJ6/';
const QH = process.argv[5] || '720';
const ROW = Number(process.argv[6] || 0);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class WS {
  constructor(url) { this.url = url; this.id = 0; this.pending = new Map(); }
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
      setTimeout(() => { if (this.pending.has(id)) { this.pending.delete(id); rej(new Error('timeout ' + method)); } }, 300000);
    });
  }
}

const EXPR = `(async () => {
  const $ = (id) => document.getElementById(id);
  const out = { badge: null, phase1: null, phase2: null, compress: null, cmp: null, before: null, href: null };
  $('url').value = ${JSON.stringify(SHARE)};
  $('url').dispatchEvent(new Event('input'));
  out.badge = $('plat').textContent;
  $('qh').value = ${JSON.stringify(QH)};

  const rows = () => [...document.querySelectorAll('#result tbody tr:not(.cmp):not(.load)')];
  const frame = () => rows().map(tr => tr.innerText.replace(/\\s+/g,' ').trim());

  $('go').click();
  let t0 = Date.now();
  while (Date.now() - t0 < 90000) {
    await new Promise(r => setTimeout(r, 500));
    if (rows().length) { out.phase1 = { rows: frame(), elapsed: +((Date.now()-t0)/1000).toFixed(1) }; break; }
    if (/解析失败/.test($('msg').innerText)) { out.phase1 = { err: $('msg').innerText }; break; }
  }
  // 等阶段二补档（unless 用户关了 more-size）
  t0 = Date.now();
  while (Date.now() - t0 < 60000) {
    await new Promise(r => setTimeout(r, 500));
    if (!document.querySelector('#result tr.load')) break;
  }
  out.phase2 = { rows: frame(), hint: $('msg').innerText, elapsed: +((Date.now()-t0)/1000).toFixed(1) };

  const tr = rows()[${ROW}];
  if (!tr) { out.compress = { err: 'no row ${ROW}' }; return JSON.stringify(out, null, 1); }
  const btns = [...tr.querySelectorAll('button')];
  out.before = { row: tr.innerText.replace(/\\s+/g,' ').trim(), buttons: btns.map(b => b.textContent) };
  const cz = btns.find(b => b.textContent === '压缩');
  if (!cz) { out.compress = { err: 'no compress button' }; return JSON.stringify(out, null, 1); }
  if (cz.disabled) { out.compress = { err: 'compress button disabled: ' + cz.title }; return JSON.stringify(out, null, 1); }

  cz.click();
  t0 = Date.now();
  let seenBusy = false;
  while (Date.now() - t0 < 300000) {
    await new Promise(r => setTimeout(r, 500));
    if (cz.textContent === '压缩中…') seenBusy = true;
    const cmp = tr.nextElementSibling && tr.nextElementSibling.classList.contains('cmp')
              ? tr.nextElementSibling : document.querySelector('#result tbody tr.cmp');
    if (cmp) {
      const link = cmp.querySelector('a.dl');
      out.cmp = { text: cmp.innerText.replace(/\\s+/g,' ').trim(), elapsed: +((Date.now()-t0)/1000).toFixed(1) };
      out.href = link ? link.getAttribute('href') : null;
      break;
    }
    if (cz.textContent === '压缩失败' && !seenBusy) break;
  }
  out.compress = { seenBusy, btn: cz.textContent, btnDisabled: cz.disabled, elapsed: +((Date.now()-t0)/1000).toFixed(1) };
  return JSON.stringify(out, null, 1);
})()`;

(async () => {
  const r0 = await fetch(CDP + '/json/list');
  const list = await r0.json();
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
  console.log('--- 压缩画质 UI 实测 ---');
  console.log(r.result.value);
  ws.ws.close();
})().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
