'use strict';
// Liên kết Node.js với notebook .ipynb: xuất dataset từ MongoDB ra CSV, gọi Python chạy notebook,
// rồi đọc kết quả (chữ, bảng, ảnh) để web hiển thị.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const { httpErr } = require('./errors');

const ROOT = path.join(__dirname, '..', 'notebook');
const NB_FILE = path.join(ROOT, 'NoSQL_Access_Control_School_Demo.ipynb');
const RUNNER = path.join(ROOT, 'run_notebook.py');
const RUNS = path.join(ROOT, 'runs');
const EXAMPLE = path.join(ROOT, 'example');
const REQUIRED = ['school', 'age', 'G1', 'G2', 'G3']; // notebook viết cho dữ liệu học sinh kiểu UCI
const TIMEOUT_MS = 300000;
const KEEP_RUNS = 6;

const python = () => process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
const validJob = (id) => /^[a-f0-9]{16}$/.test(String(id));

// ---------- Kiểm tra môi trường ----------
let pyCache = null;
function pythonStatus() {
  if (pyCache && Date.now() - pyCache.at < 60000) return pyCache.value;
  const r = spawnSync(python(), ['-c', 'import pandas, numpy, networkx, matplotlib'], { timeout: 30000, encoding: 'utf8' });
  let value;
  if (r.error) value = { ok: false, error: `Không chạy được ${python()} (${r.error.code || r.error.message})` };
  else if (r.status !== 0) {
    const m = /No module named '([^']+)'/.exec(r.stderr || '');
    value = { ok: false, error: m ? `Python thiếu thư viện ${m[1]} (cần pandas, numpy, networkx, matplotlib)` : 'Python thiếu thư viện cần thiết' };
  } else value = { ok: true };
  pyCache = { at: Date.now(), value };
  return value;
}

function eligibility(columns) {
  const byName = new Map(columns.map((c) => [c.name, c]));
  const missing = REQUIRED.filter((n) => !byName.has(n) || (n !== 'school' && byName.get(n).type !== 'numeric'));
  return { ok: missing.length === 0, missing };
}

// ---------- Xuất CSV (dấu ;, giống file UCI) ----------
function toCSV(rows, columns) {
  const names = columns.map((c) => c.name);
  const q = (s) => `"${String(s).replace(/"/g, '""')}"`;
  const lines = [names.map(q).join(';')];
  for (const r of rows) {
    lines.push(names.map((n) => {
      const v = r[n];
      if (v === null || v === undefined) return '';
      return typeof v === 'number' ? String(v) : q(v);
    }).join(';'));
  }
  return lines.join('\n') + '\n';
}

// ---------- Công việc chạy notebook ----------
const jobs = new Map();
const running = () => [...jobs.values()].find((j) => j.status === 'running') || null;

function cleanupRuns() {
  try {
    const dirs = fs.readdirSync(RUNS, { withFileTypes: true }).filter((d) => d.isDirectory() && validJob(d.name))
      .map((d) => ({ n: d.name, t: fs.statSync(path.join(RUNS, d.name)).mtimeMs })).sort((a, b) => b.t - a.t);
    for (const d of dirs.slice(KEEP_RUNS)) fs.rmSync(path.join(RUNS, d.n), { recursive: true, force: true });
  } catch { /* bỏ qua */ }
}

function startRun({ datasetId, name, rows, columns }) {
  if (running()) throw httpErr(409, 'Đang có một lần chạy notebook khác, hãy đợi nó xong');
  const py = pythonStatus();
  if (!py.ok) throw httpErr(400, py.error);
  const el = eligibility(columns);
  if (!el.ok) throw httpErr(400, `Dataset thiếu cột số/cột cần thiết cho notebook: ${el.missing.join(', ')}`);

  const jobId = crypto.randomBytes(8).toString('hex');
  const dir = path.join(RUNS, jobId);
  fs.mkdirSync(dir, { recursive: true });
  const csv = path.join(dir, 'data.csv');
  fs.writeFileSync(csv, toCSV(rows, columns));
  fs.writeFileSync(path.join(dir, 'job.json'), JSON.stringify({ datasetId, name }));

  const job = { jobId, datasetId, name, status: 'running', startedAt: Date.now(), message: '' };
  jobs.set(jobId, job);

  const child = spawn(python(), [RUNNER, '--notebook', NB_FILE, '--out', dir, '--csv', csv, '--label', `Chạy trên dataset "${name}" (MongoDB)`], {
    env: { ...process.env, PYTHONIOENCODING: 'utf-8', MPLBACKEND: 'Agg' }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let err = '';
  child.stderr.on('data', (d) => { err = (err + d).slice(-2000); });
  child.stdout.on('data', () => {});
  const timer = setTimeout(() => { job.message = 'Quá thời gian chạy'; child.kill('SIGKILL'); }, TIMEOUT_MS);
  child.on('error', (e) => { clearTimeout(timer); job.status = 'error'; job.message = e.message; job.finishedAt = Date.now(); });
  child.on('close', (code) => {
    clearTimeout(timer);
    try { fs.rmSync(csv, { force: true }); } catch { /* bỏ qua */ }
    job.finishedAt = Date.now();
    if (job.status === 'error') return;
    if (fs.existsSync(path.join(dir, 'result.json'))) {
      const meta = JSON.parse(fs.readFileSync(path.join(dir, 'result.json'), 'utf8')).meta;
      job.status = meta.ok ? 'done' : 'error';
      job.message = meta.ok ? '' : `Lỗi ở cell ${meta.error.cell}: ${meta.error.error.trim().split('\n').pop()}`;
    } else {
      job.status = 'error';
      job.message = job.message || (err.trim().split('\n').pop() || `Python thoát với mã ${code}`);
    }
    cleanupRuns();
  });
  return jobPublic(job);
}

const jobPublic = (j) => ({
  jobId: j.jobId, datasetId: j.datasetId, status: j.status, message: j.message,
  startedAt: j.startedAt, finishedAt: j.finishedAt || null, seconds: Math.round(((j.finishedAt || Date.now()) - j.startedAt) / 100) / 10,
});

function getJob(id) {
  if (!validJob(id)) throw httpErr(400, 'Mã công việc không hợp lệ');
  const j = jobs.get(id);
  if (!j) throw httpErr(404, 'Không tìm thấy công việc');
  return jobPublic(j);
}

// Lần chạy gần nhất đã xong cho một dataset (kể cả sau khi khởi động lại server)
function latestFor(datasetId) {
  let best = null;
  try {
    for (const d of fs.readdirSync(RUNS, { withFileTypes: true })) {
      if (!d.isDirectory() || !validJob(d.name)) continue;
      const dir = path.join(RUNS, d.name);
      if (!fs.existsSync(path.join(dir, 'result.json'))) continue;
      const info = JSON.parse(fs.readFileSync(path.join(dir, 'job.json'), 'utf8'));
      if (String(info.datasetId) !== String(datasetId)) continue;
      const t = fs.statSync(path.join(dir, 'result.json')).mtimeMs;
      if (!best || t > best.t) best = { jobId: d.name, t, finishedAt: new Date(t).toISOString() };
    }
  } catch { /* bỏ qua */ }
  return best;
}

function dirFor(jobId) {
  if (!jobId) return EXAMPLE;
  if (!validJob(jobId)) throw httpErr(400, 'Mã công việc không hợp lệ');
  const d = path.join(RUNS, jobId);
  if (!fs.existsSync(d)) throw httpErr(404, 'Không tìm thấy kết quả');
  return d;
}

function readResult(jobId) {
  const f = path.join(dirFor(jobId), 'result.json');
  if (!fs.existsSync(f)) throw httpErr(404, 'Chưa có kết quả');
  return JSON.parse(fs.readFileSync(f, 'utf8'));
}

function downloadPath(kind, jobId) {
  if (kind === 'source') return { file: NB_FILE, name: 'NoSQL_Access_Control_School_Demo.ipynb' };
  const f = path.join(dirFor(jobId), 'executed.ipynb');
  if (!fs.existsSync(f)) throw httpErr(404, 'Chưa có bản đã chạy');
  return { file: f, name: 'NoSQL_Access_Control_School_Demo.executed.ipynb' };
}

const exampleAvailable = () => fs.existsSync(path.join(EXAMPLE, 'result.json'));

module.exports = {
  pythonStatus, eligibility, toCSV, startRun, getJob, latestFor, readResult, downloadPath, exampleAvailable,
  running: () => { const r = running(); return r ? jobPublic(r) : null; }, REQUIRED,
};
