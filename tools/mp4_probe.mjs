// MP4 结构探针 v2：逐 trak 报告 hdlr / stsd codec / tkhd 分辨率 / mvhd 时长
import fs from 'node:fs';
const file = process.argv[2];
const b = fs.readFileSync(file);
function findBoxes(start, end) {
  const out = [];
  let off = start;
  while (off + 8 <= end) {
    const size = b.readUInt32BE(off);
    const type = b.toString('ascii', off + 4, off + 8);
    if (size < 8 || off + size > end) { out.push({ type, off, size: end - off, bogus: true }); break; }
    out.push({ type, off, size });
    off += size;
  }
  return out;
}
function find(parent, path) {
  let cur = [{ off: parent.off, size: parent.size }];
  let box = null;
  for (const want of path) {
    box = null;
    for (const c of cur) for (const x of findBoxes(c.off + (c.type === undefined ? 8 : 8), c.off + c.size)) if (x.type === want) { box = x; break; }
    if (!box) return null;
    cur = [box];
  }
  return box;
}
const top = findBoxes(0, b.length);
console.log(`FILE ${file}  ${b.length} bytes  top=[${top.map((t) => t.type).join(',')}]`);
const moov = top.find((t) => t.type === 'moov');
const mvhd = find(moov, ['mvhd']);
if (mvhd) {
  const off = mvhd.off;
  const ver = b[off + 8];
  const ts = b.readUInt32BE(off + (ver === 1 ? 28 : 20));
  const dur = ver === 1 ? Number(b.readBigUInt64BE(off + 32)) : b.readUInt32BE(off + 24);
  console.log(`  mvhd: ${(dur / ts).toFixed(2)}s @timescale ${ts}`);
}
const traks = findBoxes(moov.off + 8, moov.off + moov.size).filter((x) => x.type === 'trak');
for (const [i, trak] of traks.entries()) {
  const hdlr = find(trak, ['mdia', 'hdlr']);
  const handler = hdlr ? b.toString('ascii', hdlr.off + 24, hdlr.off + 28) : '?';
  const stsd = find(trak, ['mdia', 'minf', 'stbl', 'stsd']);
  const fmt = stsd ? b.toString('ascii', stsd.off + 20, stsd.off + 24) : '?';
  const tkhd = find(trak, ['tkhd']);
  let dim = '?';
  if (tkhd) {
    const ver = b[tkhd.off + 8];
    const w = b.readUInt32BE(tkhd.off + (ver === 1 ? 96 : 84)) / 65536;
    const h = b.readUInt32BE(tkhd.off + (ver === 1 ? 100 : 88)) / 65536;
    dim = `${w}x${h}`;
  }
  // 音视频码率粗估：用 stsz 总字节 / 时长
  console.log(`  trak#${i}: handler=${handler} codec=${fmt} dim=${dim}${hdlr && handler === 'soun' ? ' (音频轨)' : ''}`);
}
