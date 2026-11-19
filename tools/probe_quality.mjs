// 高码率变体：跟随 302 看最终直链 + 体积/分辨率探测
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const urls = process.argv.slice(2);
for (const u of urls) {
  try {
    const r = await fetch(u, { redirect: 'follow', headers: { 'user-agent': UA, referer: 'https://www.hellotik.app/zh/douyin' } });
    const buf = Buffer.from(await r.arrayBuffer());
    console.log('---');
    console.log('final :', r.url.slice(0, 130));
    console.log('status:', r.status, '| content-length:', r.headers.get('content-length'), '| type:', r.headers.get('content-type'));
    console.log('bytes :', buf.length, '| magic:', buf.slice(4, 12).toString('hex'));
    // 从 moov/tkhd 抓宽高（简易扫描 0x74 0x6b 0x68 0x64）
    const i = buf.indexOf(Buffer.from('tkhd'));
    if (i > 0 && buf.length > i + 92) {
      const w = buf.readUInt32BE(i + 76) / 65536, h = buf.readUInt32BE(i + 84) / 65536;
      console.log('tkhd  :', w + 'x' + h);
    }
  } catch (e) { console.log('---\nFAIL', u.slice(0, 80), e.message); }
}
