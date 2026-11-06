'use strict';
const path = require('path');
const fs = require('fs');
const express = require('express');
const multer = require('multer');
const { MongoClient, ObjectId } = require('mongodb');

const { parseBuffer, inferSchema } = require('./lib/ingest');
const { fetchBuffer } = require('./lib/fetchurl');
const { httpErr } = require('./lib/errors');
const stats = require('./lib/stats');
const acl = require('./lib/acl');
const nbk = require('./lib/notebook');

const PORT = Number(process.env.PORT) || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017';
const DB_NAME = process.env.MONGODB_DB || 'so_diem';
const MAX_UPLOAD = 50 * 1024 * 1024;

const client = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
let db, datasets, records, policies, audit;

// ---------- Bộ nhớ đệm nhỏ để không đọc lại cả dataset cho mỗi biểu đồ ----------
const rowsCache = new Map();
const statsCache = new Map();
function remember(map, key, value, max = 4) {
  map.set(key, value);
  if (map.size > max) map.delete(map.keys().next().value);
  return value;
}
function forget(id) { rowsCache.delete(id); statsCache.delete(id); }

// ---------- Dữ liệu ----------
const cleanName = (s) => String(s || '').trim().slice(0, 80);

async function saveDataset(name, source, rows) {
  if (!rows.length) throw httpErr(400, 'Không có dòng dữ liệu nào');
  const columns = inferSchema(rows);
  const ins = await datasets.insertOne({ name, source, createdAt: new Date(), rowCount: rows.length, columns });
  try {
    for (let i = 0; i < rows.length; i += 1000) {
      const batch = rows.slice(i, i + 1000).map((data, j) => ({ datasetId: ins.insertedId, rid: i + j + 1, data }));
      await records.insertMany(batch, { ordered: true });
    }
  } catch (e) {
    await records.deleteMany({ datasetId: ins.insertedId });
    await datasets.deleteOne({ _id: ins.insertedId });
    throw e;
  }
  return { id: String(ins.insertedId), name, rowCount: rows.length, colCount: columns.length };
}

async function loadDataset(id) {
  if (!ObjectId.isValid(id)) throw httpErr(400, 'ID dataset không hợp lệ');
  const _id = new ObjectId(id);
  const ds = await datasets.findOne({ _id });
  if (!ds) throw httpErr(404, 'Không tìm thấy dataset');
  let rows = rowsCache.get(id);
  if (!rows) {
    const docs = await records.find({ datasetId: _id }).sort({ rid: 1 }).project({ data: 1 }).toArray();
    rows = remember(rowsCache, id, docs.map((d) => d.data));
  }
  return { ds, rows };
}

const summary = (d) => ({
  id: String(d._id), name: d.name, rowCount: d.rowCount, colCount: d.columns.length,
  source: d.source, createdAt: d.createdAt,
});
const colByName = (ds, n, type) => {
  const c = ds.columns.find((x) => x.name === n);
  if (!c) throw httpErr(400, `Không có cột "${n}"`);
  if (type && c.type !== type) throw httpErr(400, `Cột "${n}" không phải kiểu ${type}`);
  return c;
};

// ---------- App ----------
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/vendor/chart.js', (req, res) => {
  const dir = path.join(__dirname, 'node_modules', 'chart.js', 'dist');
  const file = ['chart.umd.js', 'chart.umd.min.js'].map((n) => path.join(dir, n)).find((p) => fs.existsSync(p));
  if (!file) return res.status(404).send('Chưa cài chart.js, hãy chạy npm install');
  res.sendFile(file);
});

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_UPLOAD, files: 1 } });
const h = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.get('/api/health', h(async (req, res) => {
  try { await db.command({ ping: 1 }); res.json({ ok: true, db: DB_NAME }); }
  catch { res.status(503).json({ ok: false }); }
}));

app.get('/api/datasets', h(async (req, res) => {
  const list = await datasets.find().sort({ createdAt: -1 }).toArray();
  res.json(list.map(summary));
}));

app.post('/api/datasets/upload', upload.single('file'), h(async (req, res) => {
  if (!req.file) throw httpErr(400, 'Chưa chọn file');
  const parsed = parseBuffer(req.file.buffer, req.file.originalname);
  const name = cleanName(req.body.name) || req.file.originalname.replace(/\.[^.]+$/, '');
  res.status(201).json(await saveDataset(name, { type: 'file', value: req.file.originalname, entry: parsed.entry || null }, parsed.rows));
}));

app.post('/api/datasets/url', h(async (req, res) => {
  const url = String((req.body && req.body.url) || '').trim();
  if (!url) throw httpErr(400, 'Chưa nhập link');
  const { buf, filename, finalUrl } = await fetchBuffer(url);
  const parsed = parseBuffer(buf, filename);
  const name = cleanName(req.body.name) || filename.replace(/\.[^.]+$/, '');
  res.status(201).json(await saveDataset(name, { type: 'url', value: finalUrl, entry: parsed.entry || null }, parsed.rows));
}));

app.delete('/api/datasets/:id', h(async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) throw httpErr(400, 'ID dataset không hợp lệ');
  const _id = new ObjectId(req.params.id);
  await records.deleteMany({ datasetId: _id });
  const r = await datasets.deleteOne({ _id });
  forget(req.params.id);
  if (!r.deletedCount) throw httpErr(404, 'Không tìm thấy dataset');
  res.json({ ok: true });
}));

app.get('/api/datasets/:id/stats', h(async (req, res) => {
  const { ds, rows } = await loadDataset(req.params.id);
  const st = statsCache.get(req.params.id) || remember(statsCache, req.params.id, stats.datasetStats(rows, ds.columns));
  res.json({ dataset: summary(ds), ...st });
}));

app.get('/api/datasets/:id/groupby', h(async (req, res) => {
  const { ds, rows } = await loadDataset(req.params.id);
  const by = colByName(ds, String(req.query.by || '')).name;
  const metric = req.query.metric ? colByName(ds, String(req.query.metric), 'numeric').name : null;
  res.json({ by, metric, groups: stats.groupBy(rows, by, metric) });
}));

app.get('/api/datasets/:id/scatter', h(async (req, res) => {
  const { ds, rows } = await loadDataset(req.params.id);
  const x = colByName(ds, String(req.query.x || ''), 'numeric').name;
  const y = colByName(ds, String(req.query.y || ''), 'numeric').name;
  res.json({ x, y, ...stats.scatter(rows, x, y) });
}));

app.get('/api/policies', h(async (req, res) => {
  res.json({ policies: await policies.find().toArray(), groups: acl.GROUPS });
}));

// Hồ sơ được lọc theo vai trò: chỉ các trường được phép rời khỏi server.
// Lưu ý: vai trò ở đây chỉ để minh hoạ, chưa có đăng nhập thật.
app.get('/api/datasets/:id/records', h(async (req, res) => {
  const { ds, rows } = await loadDataset(req.params.id);
  const subject = acl.cleanSubject(req.query);
  const pol = await policies.find().toArray();
  const names = ds.columns.map((c) => c.name);
  const schoolField = names.includes('school') ? 'school' : null;

  let visible = 0, locked = 0;
  let list = [];
  rows.forEach((row, i) => {
    if (!acl.inScope(subject, row, schoolField)) return;
    const p = acl.project(subject, pol, row, names);
    visible += Object.keys(p.data).length;
    locked += p.locked;
    list.push({ rid: i + 1, data: p.data, locked: p.locked });
  });

  // Tìm kiếm chỉ trên các giá trị người dùng được phép thấy, tránh dò ra dữ liệu bị ẩn
  const q = String(req.query.q || '').toLowerCase().trim().slice(0, 100);
  if (q) list = list.filter((r) => Object.values(r.data).some((v) => String(v).toLowerCase().includes(q)));

  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
  const pages = Math.max(Math.ceil(list.length / limit), 1);
  const page = Math.min(Math.max(parseInt(req.query.page, 10) || 1, 1), pages);

  audit.insertOne({
    ts: new Date(), datasetId: String(ds._id), datasetName: ds.name, role: subject.role, school: subject.school,
    trained: subject.trained, rows: list.length, visibleCells: visible, lockedCells: locked, searched: !!q,
  }).catch((e) => console.error('audit:', e.message));

  res.json({
    total: list.length, page, pages, limit,
    columns: ds.columns.map((c) => ({ name: c.name, type: c.type, group: acl.groupOf(c.name) })),
    rows: list.slice((page - 1) * limit, page * limit),
    summary: { visibleCells: visible, lockedCells: locked },
  });
}));

app.get('/api/audit', h(async (req, res) => {
  const list = await audit.find().sort({ ts: -1 }).limit(12).toArray();
  res.json(list.map((a) => ({
    ts: a.ts, role: a.role, school: a.school, trained: a.trained, rows: a.rows,
    visibleCells: a.visibleCells, lockedCells: a.lockedCells, dataset: a.datasetName, searched: a.searched,
  })));
}));


// ---------- Liên kết với notebook .ipynb ----------
app.get('/api/notebook/info', h(async (req, res) => {
  let eligible = null, latest = null;
  if (req.query.datasetId) {
    const { ds } = await loadDataset(String(req.query.datasetId));
    eligible = nbk.eligibility(ds.columns);
    latest = nbk.latestFor(String(ds._id));
  }
  res.json({ python: nbk.pythonStatus(), required: nbk.REQUIRED, eligible, latest, running: nbk.running(), example: nbk.exampleAvailable() });
}));

app.post('/api/notebook/run', h(async (req, res) => {
  const { ds, rows } = await loadDataset(String((req.body && req.body.datasetId) || ''));
  res.status(202).json(nbk.startRun({ datasetId: String(ds._id), name: ds.name, rows, columns: ds.columns }));
}));

app.get('/api/notebook/jobs/:id', h(async (req, res) => { res.json(nbk.getJob(req.params.id)); }));

// Không có jobId = kết quả mẫu đi kèm
app.get('/api/notebook/result', h(async (req, res) => { res.json(nbk.readResult(req.query.jobId || null)); }));

app.get('/api/notebook/download', h(async (req, res) => {
  const { file, name } = nbk.downloadPath(req.query.kind, req.query.jobId || null);
  res.download(file, name);
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Không có API này' }));
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  const status = err.status || (err.code === 'LIMIT_FILE_SIZE' ? 413 : 500);
  if (status === 500) console.error(err);
  const msg = status === 500 ? 'Lỗi máy chủ' : err.code === 'LIMIT_FILE_SIZE' ? 'File quá lớn (tối đa 50 MB)' : err.message;
  res.status(status).json({ error: msg });
});

async function start() {
  try {
    await client.connect();
  } catch (e) {
    console.error(`Không kết nối được MongoDB tại ${MONGODB_URI}\n  -> ${e.message}\n` +
      '  Khởi động MongoDB (ví dụ: docker compose up -d) hoặc đặt MONGODB_URI rồi chạy lại.');
    process.exit(1);
  }
  db = client.db(DB_NAME);
  datasets = db.collection('datasets');
  records = db.collection('records');
  policies = db.collection('policies');
  audit = db.collection('audit');
  await records.createIndex({ datasetId: 1, rid: 1 });
  await audit.createIndex({ ts: -1 });
  if ((await policies.countDocuments()) === 0) await policies.insertMany(acl.DEFAULT_POLICIES);
  app.listen(PORT, () => console.log(`Sổ điểm đang chạy tại http://localhost:${PORT} (MongoDB: ${DB_NAME})`));
}

if (require.main === module) start();
module.exports = { app, start };
