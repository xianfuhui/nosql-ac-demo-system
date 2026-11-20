// Đọc file .xlsx tối giản, không cần thư viện ngoài (zip + XML). Chỉ lấy sheet đầu tiên, trả về mảng hàng, mỗi hàng là mảng chuỗi.
const zlib = require('zlib');
const MAX_ZIP = 3 * 1024 * 1024, MAX_XML = 8 * 1024 * 1024;

function unzip(buf) {
  if (buf.length > MAX_ZIP) throw new Error('File quá lớn (tối đa 3MB).');
  let e = buf.length - 22; while (e >= 0 && buf.readUInt32LE(e) !== 0x06054b50) e--;
  if (e < 0) throw new Error('Không phải file .xlsx hợp lệ.');
  const n = buf.readUInt16LE(e + 10); let p = buf.readUInt32LE(e + 16); const out = {};
  for (let i = 0; i < n && i < 200; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) break;
    const method = buf.readUInt16LE(p + 10), csz = buf.readUInt32LE(p + 20), nl = buf.readUInt16LE(p + 28), el = buf.readUInt16LE(p + 30), cl = buf.readUInt16LE(p + 32), off = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nl); p += 46 + nl + el + cl;
    if (!/^(xl\/(workbook\.xml|_rels\/workbook\.xml\.rels|sharedStrings\.xml|worksheets\/[^/]+\.xml))$/.test(name)) continue;
    const ds = off + 30 + buf.readUInt16LE(off + 26) + buf.readUInt16LE(off + 28), raw = buf.subarray(ds, ds + csz);
    out[name] = (method === 0 ? raw : zlib.inflateRawSync(raw, { maxOutputLength: MAX_XML })).toString('utf8');
  }
  return out;
}
const dec = s => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d)).replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16))).replace(/&amp;/g, '&');
const texts = x => [...x.matchAll(/<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g)].map(m => dec(m[1])).join('');
const colIdx = ref => { let n = 0; for (const ch of ref.replace(/\d+/g, '')) n = n * 26 + ch.charCodeAt(0) - 64; return n - 1; };

function readXlsx(buf) {
  const z = unzip(buf);
  let sheetPath = 'xl/worksheets/sheet1.xml';
  const wb = z['xl/workbook.xml'], rel = z['xl/_rels/workbook.xml.rels'];
  if (wb && rel) {
    const rid = (wb.match(/<sheet\b[^>]*\br:id="([^"]+)"/) || [])[1];
    const t = rid && [...rel.matchAll(/<Relationship\b[^>]*>/g)].map(m => m[0]).find(r => new RegExp(`\\bId="${rid}"`).test(r));
    const tg = t && (t.match(/\bTarget="([^"]+)"/) || [])[1];
    if (tg) sheetPath = tg.startsWith('/') ? tg.slice(1) : 'xl/' + tg.replace(/^\.\//, '');
  }
  const xml = z[sheetPath] || Object.entries(z).find(([k]) => k.startsWith('xl/worksheets/'))?.[1];
  if (!xml) throw new Error('Không tìm thấy sheet dữ liệu trong file.');
  const sst = z['xl/sharedStrings.xml'] ? [...z['xl/sharedStrings.xml'].matchAll(/<si\b[^>]*>([\s\S]*?)<\/si>/g)].map(m => texts(m[1])) : [];
  const rows = [];
  for (const rm of xml.matchAll(/<row\b[^>]*>([\s\S]*?)<\/row>/g)) {
    const row = [];
    for (const cm of rm[1].matchAll(/<c\b([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)) {
      const at = cm[1], body = cm[2] || '', ref = (at.match(/\br="([A-Z]+\d+)"/) || [])[1], ty = (at.match(/\bt="(\w+)"/) || [])[1];
      if (!ref) continue;
      const v = (body.match(/<v>([\s\S]*?)<\/v>/) || [])[1];
      row[colIdx(ref)] = ty === 's' ? (sst[+v] ?? '') : ty === 'inlineStr' ? texts(body) : v === undefined ? '' : dec(v);
    }
    rows.push(Array.from(row, x => (x ?? '').toString()));
    if (rows.length > 2000) break;
  }
  return rows;
}
module.exports = { readXlsx };
