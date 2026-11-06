'use strict';
const isNum = (v) => typeof v === 'number' && Number.isFinite(v);
const round = (x, d = 2) => Math.round(x * 10 ** d) / 10 ** d;

function nums(rows, name) {
  const out = [];
  for (const r of rows) if (isNum(r[name])) out.push(r[name]);
  return out;
}
function mean(a) {
  if (!a.length) return null;
  let s = 0;
  for (const x of a) s += x;
  return s / a.length;
}
function median(a) {
  if (!a.length) return null;
  const s = [...a].sort((x, y) => x - y);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

function histogram(vals) {
  if (!vals.length) return null;
  let min = Infinity, max = -Infinity, allInt = true;
  for (const v of vals) {
    if (v < min) min = v;
    if (v > max) max = v;
    if (!Number.isInteger(v)) allInt = false;
  }
  if (allInt && max - min <= 30) {
    const counts = new Array(max - min + 1).fill(0);
    for (const v of vals) counts[v - min]++;
    return { integer: true, labels: counts.map((_, i) => String(min + i)), counts, min, max };
  }
  const bins = 12;
  const w = (max - min) / bins || 1;
  const counts = new Array(bins).fill(0);
  for (const v of vals) {
    let i = Math.floor((v - min) / w);
    if (i >= bins) i = bins - 1;
    counts[i]++;
  }
  const fmt = (x) => (Math.abs(x) >= 100 ? String(Math.round(x)) : String(round(x, 1)));
  const labels = counts.map((_, i) => `${fmt(min + i * w)}–${fmt(min + (i + 1) * w)}`);
  return { integer: false, labels, counts, min, max };
}

function topValues(rows, name, k = 12) {
  const m = new Map();
  for (const r of rows) {
    const v = r[name];
    if (v === null || v === undefined) continue;
    m.set(v, (m.get(v) || 0) + 1);
  }
  return [...m.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, k)
    .map(([value, count]) => ({ value: String(value), count }));
}

function pearson(rows, a, b) {
  let n = 0, sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0;
  for (const r of rows) {
    const x = r[a], y = r[b];
    if (!isNum(x) || !isNum(y)) continue;
    n++; sx += x; sy += y; sxx += x * x; syy += y * y; sxy += x * y;
  }
  if (n < 3) return null;
  const vx = sxx - (sx * sx) / n, vy = syy - (sy * sy) / n;
  if (vx <= 0 || vy <= 0) return null;
  return round((sxy - (sx * sy) / n) / Math.sqrt(vx * vy), 3);
}

// Chọn tối đa 10 cột số: cột đích + 9 cột tương quan mạnh nhất với nó
function correlation(rows, columns) {
  const numeric = columns.filter((c) => c.type === 'numeric' && c.distinct > 1).map((c) => c.name);
  if (numeric.length < 2) return null;
  const target = numeric.includes('G3') ? 'G3' : numeric[numeric.length - 1];
  const ranked = numeric
    .filter((n) => n !== target)
    .map((n) => ({ n, r: Math.abs(pearson(rows, target, n) ?? 0) }))
    .sort((a, b) => b.r - a.r)
    .slice(0, 9)
    .map((x) => x.n);
  const cols = [target, ...ranked];
  const matrix = cols.map((a) => cols.map((b) => (a === b ? 1 : pearson(rows, a, b))));
  return { target, cols, matrix };
}

function datasetStats(rows, columns) {
  const cols = columns.map((c) => {
    if (c.type === 'numeric') {
      const v = nums(rows, c.name);
      const hist = histogram(v);
      return { ...c, mean: round(mean(v) ?? 0), median: median(v), min: hist ? hist.min : null, max: hist ? hist.max : null, hist };
    }
    if (c.type === 'category') return { ...c, top: topValues(rows, c.name) };
    return c;
  });
  const numeric = cols.filter((c) => c.type === 'numeric');
  const primary = (numeric.find((c) => c.name === 'G3') || numeric[numeric.length - 1] || {}).name || null;
  return { rowCount: rows.length, columns: cols, primary, correlation: correlation(rows, columns) };
}

// Trung bình (hoặc đếm) của một cột số theo nhóm của một cột phân loại
function groupBy(rows, by, metric) {
  const m = new Map();
  for (const r of rows) {
    const k = r[by];
    if (k === null || k === undefined) continue;
    const e = m.get(k) || { count: 0, sum: 0, n: 0 };
    e.count++;
    if (metric && isNum(r[metric])) { e.sum += r[metric]; e.n++; }
    m.set(k, e);
  }
  const out = [...m.entries()].map(([key, e]) => ({
    key: String(key), count: e.count, mean: metric && e.n ? round(e.sum / e.n) : null,
  }));
  const numericKeys = out.every((o) => o.key !== '' && !Number.isNaN(Number(o.key)));
  if (numericKeys) out.sort((a, b) => Number(a.key) - Number(b.key));
  else out.sort((a, b) => (metric ? (b.mean ?? -Infinity) - (a.mean ?? -Infinity) : b.count - a.count));
  return out.slice(0, 30);
}

// Gộp các điểm trùng toạ độ (điểm số nguyên rất hay trùng) để vẽ bubble theo số lượng
function scatter(rows, x, y, limit = 2000) {
  const m = new Map();
  let n = 0;
  for (const r of rows) {
    if (!isNum(r[x]) || !isNum(r[y])) continue;
    n++;
    const k = `${r[x]}|${r[y]}`;
    const e = m.get(k);
    if (e) e.n++; else m.set(k, { x: r[x], y: r[y], n: 1 });
  }
  return { points: [...m.values()].slice(0, limit), total: n, r: pearson(rows, x, y) };
}

module.exports = { datasetStats, groupBy, scatter, pearson, histogram };
