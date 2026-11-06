'use strict';
// Đọc CSV / JSON / ZIP (kể cả zip lồng nhau) mà không cần thư viện ngoài.
const zlib = require('zlib');
const { httpErr } = require('./errors');

const MAX_ROWS = 100000;
const MAX_COLS = 200;
const MAX_UNZIPPED = 100 * 1024 * 1024;

// ---------- ZIP ----------
function zipEntries(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw httpErr(400, 'File zip không hợp lệ');
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  const out = [];
  for (let n = 0; n < count; n++) {
    if (off + 46 > buf.length || buf.readUInt32LE(off) !== 0x02014b50) throw httpErr(400, 'File zip bị hỏng');
    const nlen = buf.readUInt16LE(off + 28), elen = buf.readUInt16LE(off + 30), clen = buf.readUInt16LE(off + 32);
    out.push({
      method: buf.readUInt16LE(off + 10),
      csize: buf.readUInt32LE(off + 20),
      usize: buf.readUInt32LE(off + 24),
      lho: buf.readUInt32LE(off + 42),
      name: buf.toString('utf8', off + 46, off + 46 + nlen),
    });
    off += 46 + nlen + elen + clen;
  }
  return out;
}

function zipRead(buf, e) {
  if (e.csize === 0xffffffff || e.usize === 0xffffffff) throw httpErr(400, 'Zip64 chưa được hỗ trợ');
  if (e.usize > MAX_UNZIPPED) throw httpErr(413, 'File trong zip quá lớn');
  if (buf.readUInt32LE(e.lho) !== 0x04034b50) throw httpErr(400, 'File zip bị hỏng');
  const start = e.lho + 30 + buf.readUInt16LE(e.lho + 26) + buf.readUInt16LE(e.lho + 28);
  const data = buf.subarray(start, start + e.csize);
  if (e.method === 0) return Buffer.from(data);
  if (e.method === 8) return zlib.inflateRawSync(data, { maxOutputLength: MAX_UNZIPPED });
  throw httpErr(400, 'Kiểu nén trong zip chưa được hỗ trợ');
}

function parseZip(buf, depth = 0) {
  if (depth > 2) throw httpErr(400, 'Zip lồng quá sâu');
  const entries = zipEntries(buf)
    .filter((e) => !e.name.endsWith('/') && !/(^|\/)(__MACOSX|\.)/.test(e.name))
    .sort((a, b) => a.name.localeCompare(b.name));
  const pick =
    entries.find((e) => /\.(csv|tsv)$/i.test(e.name)) ||
    entries.find((e) => /\.json$/i.test(e.name)) ||
    entries.find((e) => /\.zip$/i.test(e.name));
  if (!pick) throw httpErr(400, 'Trong zip không có file .csv, .tsv hoặc .json');
  const inner = zipRead(buf, pick);
  if (/\.zip$/i.test(pick.name)) return parseZip(inner, depth + 1);
  return { ...parseBuffer(inner, pick.name, depth + 1), entry: pick.name };
}

// ---------- CSV ----------
function detectDelimiter(text) {
  const first = text.split(/\r?\n/, 1)[0];
  let best = ',', bestN = 0;
  for (const d of [',', ';', '\t', '|']) {
    let n = 0, q = false;
    for (const ch of first) {
      if (ch === '"') q = !q;
      else if (!q && ch === d) n++;
    }
    if (n > bestN) { best = d; bestN = n; }
  }
  return best;
}

function uniqueKey(raw, i, used) {
  const k0 = String(raw ?? '').trim().replace(/\./g, '_').replace(/^\$/, '_') || `cot_${i + 1}`;
  let k = k0, n = 2;
  while (used.has(k)) k = `${k0}_${n++}`;
  used.add(k);
  return k;
}

const NUM = /^-?\d+(\.\d+)?([eE][-+]?\d+)?$/;
function coerce(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === 'number' || typeof v === 'boolean') return v;
  if (typeof v !== 'string') return JSON.stringify(v);
  const t = v.trim();
  if (t === '') return null;
  if (NUM.test(t) && !/^-?0\d/.test(t)) { const x = Number(t); if (Number.isFinite(x)) return x; }
  return t;
}

function parseCSV(text) {
  const d = detectDelimiter(text);
  const table = [];
  let row = [], field = '', q = false;
  const n = text.length;
  const endRow = () => {
    row.push(field); field = '';
    if (row.length > 1 || row[0] !== '') table.push(row);
    row = [];
    if (table.length > MAX_ROWS + 1) throw httpErr(413, `Quá ${MAX_ROWS} dòng`);
  };
  for (let i = 0; i < n; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; }
      else field += c;
    } else if (c === '"' && field === '') q = true;
    else if (c === d) { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; endRow(); }
    else field += c;
  }
  if (field !== '' || row.length) endRow();
  if (table.length < 2) throw httpErr(400, 'File cần có dòng tiêu đề và ít nhất một dòng dữ liệu');

  const used = new Set();
  const header = table[0].map((h, i) => uniqueKey(h, i, used));
  if (header.length > MAX_COLS) throw httpErr(413, `Quá ${MAX_COLS} cột`);
  return table.slice(1).map((cells) => {
    const o = {};
    header.forEach((h, i) => { o[h] = coerce(cells[i]); });
    return o;
  });
}

// ---------- JSON ----------
function parseJSON(text) {
  let data;
  try { data = JSON.parse(text); } catch { throw httpErr(400, 'JSON không hợp lệ'); }
  if (!Array.isArray(data)) data = data && (data.data || data.records || data.rows || data.items);
  if (!Array.isArray(data) || !data.length || typeof data[0] !== 'object' || data[0] === null) {
    throw httpErr(400, 'JSON cần là mảng các đối tượng');
  }
  if (data.length > MAX_ROWS) throw httpErr(413, `Quá ${MAX_ROWS} dòng`);
  const used = new Set();
  const map = new Map();
  const keyFor = (k) => { if (!map.has(k)) map.set(k, uniqueKey(k, map.size, used)); return map.get(k); };
  return data.map((r) => {
    const o = {};
    for (const k of Object.keys(r || {})) o[keyFor(k)] = coerce(r[k]);
    return o;
  });
}

// ---------- Điểm vào ----------
function parseBuffer(buf, filename = '', depth = 0) {
  if (!buf || !buf.length) throw httpErr(400, 'File rỗng');
  if (buf.length > 3 && buf[0] === 0x50 && buf[1] === 0x4b) return parseZip(buf, depth);
  const text = buf.toString('utf8').replace(/^\uFEFF/, '');
  const head = text.trimStart()[0];
  if (head === '<') {
    throw httpErr(400, 'Nội dung là trang web (HTML), không phải dữ liệu. Hãy dùng link tải trực tiếp tới file .csv, .json hoặc .zip');
  }
  if (/\.json$/i.test(filename) || head === '[' || head === '{') return { rows: parseJSON(text), entry: filename };
  return { rows: parseCSV(text), entry: filename };
}

// ---------- Suy luận kiểu cột ----------
function inferSchema(rows) {
  const names = [];
  const seen = new Set();
  for (const r of rows) for (const k of Object.keys(r)) if (!seen.has(k)) { seen.add(k); names.push(k); }
  return names.map((name) => {
    let nonNull = 0, numeric = 0, nulls = 0;
    const distinct = new Set();
    for (const r of rows) {
      const v = r[name];
      if (v === null || v === undefined) { nulls++; continue; }
      nonNull++;
      if (typeof v === 'number') numeric++;
      if (distinct.size <= 1000) distinct.add(v);
    }
    let type = 'text';
    if (nonNull && numeric / nonNull >= 0.95) type = 'numeric';
    else if (distinct.size <= 50 || distinct.size / Math.max(nonNull, 1) <= 0.5) type = 'category';
    return { name, type, distinct: distinct.size, nulls };
  });
}

module.exports = { parseBuffer, parseCSV, inferSchema, coerce };
