'use strict';
// Chạy: node test/run.js
// Kiểm thử module lõi bằng dữ liệu thật trong sample/, và kiểm thử server.js bằng bản giả lập express/mongodb.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const Module = require('module');
const zlib = require('zlib');

const stubs = { express: 'express', multer: 'multer', mongodb: 'mongodb' };
const orig = Module._resolveFilename;
Module._resolveFilename = function (req, ...rest) {
  if (stubs[req]) return path.join(__dirname, 'stubs', stubs[req] + '.js');
  return orig.call(this, req, ...rest);
};
process.env.ALLOW_PRIVATE_URLS = '1';

const { parseBuffer, parseCSV, inferSchema } = require('../lib/ingest');
const stats = require('../lib/stats');
const acl = require('../lib/acl');
const { isPrivate } = require('../lib/fetchurl');

let pass = 0;
const t = async (name, fn) => {
  try { await fn(); pass++; console.log('  ok  ', name); }
  catch (e) { console.error('  FAIL', name, '\n      ', e.message); process.exitCode = 1; }
};

(async () => {
  const csvBuf = fs.readFileSync(path.join(__dirname, '..', 'sample', 'sample-synthetic-students.csv'));

  console.log('ingest');
  await t('CSV dấu ; có nháy kép, 395 dòng, 33 cột, ép số', () => {
    const { rows } = parseBuffer(csvBuf, 'x.csv');
    assert.equal(rows.length, 395);
    assert.equal(Object.keys(rows[0]).length, 33);
    assert.equal(typeof rows[0].G3, 'number'); assert.equal(typeof rows[0].school, 'string');
  });
  await t('CSV dấu phẩy, BOM, xuống dòng trong ô, tiêu đề trùng, số 0 đầu', () => {
    const r = parseCSV('\uFEFFid,name,name,note\r\n007,An,"B, ""x""","a\nb"\r\n8,Bình,,\r\n'.replace('\uFEFF', ''));
    assert.deepEqual(Object.keys(r[0]), ['id', 'name', 'name_2', 'note']);
    assert.equal(r[0].id, '007'); assert.equal(r[0].name_2, 'B, "x"'); assert.equal(r[0].note, 'a\nb');
    assert.equal(r[1].id, 8); assert.equal(r[1].name_2, null);
  });
  await t('JSON mảng và {data:[...]}', () => {
    assert.equal(parseBuffer(Buffer.from('[{"a":1,"b.c":"x"}]'), 'a.json').rows[0]['b_c'], 'x');
    assert.equal(parseBuffer(Buffer.from('{"data":[{"a":1}]}'), 'a.json').rows.length, 1);
  });
  await t('ZIP phẳng và ZIP lồng nhau (kiểu UCI), chọn student-mat.csv', () => {
    for (const f of [path.join(__dirname,'fixtures','flat.zip'), path.join(__dirname,'fixtures','nested.zip')]) {
      const r = parseBuffer(fs.readFileSync(f), 'x.zip');
      assert.equal(r.rows.length, 395); assert.equal(r.entry, 'student-mat.csv');
    }
  });
  await t('HTML bị từ chối với thông báo rõ ràng', () => {
    assert.throws(() => parseBuffer(Buffer.from('<!doctype html><html>'), 'p'), /HTML/);
  });
  await t('File rỗng và zip hỏng bị từ chối', () => {
    assert.throws(() => parseBuffer(Buffer.alloc(0)), /rỗng/);
    assert.throws(() => parseBuffer(Buffer.from('PK\u0003\u0004xxxx')), /zip/i);
  });
  const rows = parseBuffer(csvBuf, 'x.csv').rows;
  const cols = inferSchema(rows);
  await t('suy luận kiểu cột', () => {
    const ty = Object.fromEntries(cols.map((c) => [c.name, c.type]));
    assert.equal(ty.G3, 'numeric'); assert.equal(ty.school, 'category'); assert.equal(ty.Mjob, 'category');
  });

  console.log('stats');
  const st = stats.datasetStats(rows, cols);
  await t('thống kê: primary=G3, histogram số nguyên, tương quan', () => {
    assert.equal(st.primary, 'G3'); assert.equal(st.rowCount, 395);
    const g3 = st.columns.find((c) => c.name === 'G3');
    assert.ok(g3.hist.integer); assert.equal(g3.hist.counts.reduce((a, b) => a + b, 0), 395);
    assert.equal(st.correlation.target, 'G3'); assert.equal(st.correlation.cols.length, 10);
    assert.ok(st.correlation.matrix[0][1] !== null);
    const r = stats.pearson(rows, 'G1', 'G3'); assert.ok(r > 0.7, 'G1-G3 phải tương quan mạnh, r=' + r);
  });
  await t('groupBy và scatter', () => {
    const g = stats.groupBy(rows, 'school', 'G3'); assert.equal(g.length, 2); assert.ok(g[0].mean > 0);
    const s = stats.scatter(rows, 'G1', 'G3'); assert.equal(s.total, 395);
    assert.equal(s.points.reduce((a, p) => a + p.n, 0), 395);
  });

  console.log('acl & chống SSRF');
  const names = cols.map((c) => c.name);
  const pol = acl.DEFAULT_POLICIES;
  const row = rows.find((r) => r.G2 < 10) || rows[0];
  await t('teacher đã tập huấn chỉ thấy nhóm academic', () => {
    const p = acl.project({ role: 'teacher', trained: true, school: row.school }, pol, row, names);
    assert.ok(Object.keys(p.data).every((k) => acl.GROUPS.academic.includes(k)));
    assert.equal(Object.keys(p.data).length, acl.GROUPS.academic.length);
  });
  await t('teacher chưa tập huấn không thấy gì; unknown role -> teacher', () => {
    assert.equal(Object.keys(acl.project({ role: 'teacher', trained: false }, pol, row, names).data).length, 0);
    assert.equal(acl.cleanSubject({ role: 'hacker' }).role, 'teacher');
  });
  await t('counselor: personal luôn, academic chỉ khi G2<10', () => {
    const s = { role: 'counselor', school: row.school };
    const risk = acl.project(s, pol, { ...row, G2: 5 }, names).data;
    const fine = acl.project(s, pol, { ...row, G2: 15 }, names).data;
    assert.ok('G3' in risk && !('G3' in fine) && 'health' in fine && !('Mjob' in risk));
  });
  await t('admin thấy tất cả; phạm vi trường', () => {
    assert.equal(Object.keys(acl.project({ role: 'admin', school: '*' }, pol, row, names).data).length, names.length);
    assert.ok(!acl.inScope({ role: 'teacher', school: 'GP' }, { school: 'MS' }, 'school'));
    assert.ok(!acl.inScope({ role: 'teacher', school: '*' }, { school: 'GP' }, 'school'));
  });
  await t('isPrivate chặn địa chỉ nội bộ', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.1.1', '172.20.0.1', '169.254.169.254', '::1', 'fd00::1', '::ffff:127.0.0.1']) assert.ok(isPrivate(ip), ip);
    for (const ip of ['8.8.8.8', '1.1.1.1', '172.32.0.1']) assert.ok(!isPrivate(ip), ip);
  });

  console.log('server (express/mongodb giả lập)');
  const { app, start } = require('../server');
  await start();
  const get = (u, query) => app.handle('GET', u, { query });
  let id1, id2;
  await t('upload CSV và zip lồng nhau', async () => {
    let r = await app.handle('POST', '/api/datasets/upload', { file: { buffer: csvBuf, originalname: 'mau.csv' }, body: { name: 'Mẫu' } });
    assert.equal(r.code, 201); assert.equal(r.body.rowCount, 395); id1 = r.body.id;
    r = await app.handle('POST', '/api/datasets/upload', { file: { buffer: fs.readFileSync(path.join(__dirname,'fixtures','nested.zip')), originalname: 'student.zip' }, body: {} });
    assert.equal(r.code, 201); assert.equal(r.body.name, 'student'); id2 = r.body.id;
  });
  await t('upload thiếu file / file rỗng -> 400', async () => {
    assert.equal((await app.handle('POST', '/api/datasets/upload', { body: {} })).code, 400);
    assert.equal((await app.handle('POST', '/api/datasets/upload', { file: { buffer: Buffer.alloc(0), originalname: 'a.csv' }, body: {} })).code, 400);
  });
  await t('nhập từ link (fetch giả) và từ chối trang HTML', async () => {
    const realFetch = global.fetch;
    global.fetch = async (u) => new Response(u.pathname.endsWith('.html') ? '<html></html>' : csvBuf, { status: 200 });
    let r = await app.handle('POST', '/api/datasets/url', { body: { url: 'https://example.org/data/students.csv' } });
    assert.equal(r.code, 201); assert.equal(r.body.name, 'students'); const id3 = r.body.id;
    r = await app.handle('POST', '/api/datasets/url', { body: { url: 'https://example.org/page.html' } });
    assert.equal(r.code, 400); assert.match(r.body.error, /HTML/);
    r = await app.handle('POST', '/api/datasets/url', { body: { url: 'ftp://x/y.csv' } }); assert.equal(r.code, 400);
    global.fetch = realFetch;
    await app.handle('DELETE', `/api/datasets/${id3}`);
  });
  await t('SSRF: bật chặn thì link 127.0.0.1 bị từ chối', async () => {
    process.env.ALLOW_PRIVATE_URLS = '0';
    const r = await app.handle('POST', '/api/datasets/url', { body: { url: 'http://127.0.0.1:27017/x.csv' } });
    process.env.ALLOW_PRIVATE_URLS = '1';
    assert.equal(r.code, 400); assert.match(r.body.error, /nội bộ/);
  });
  await t('danh sách, stats, groupby, scatter, policies', async () => {
    assert.equal((await get('/api/datasets')).body.length, 2);
    const s = await get(`/api/datasets/${id1}/stats`); assert.equal(s.body.rowCount, 395); assert.equal(s.body.primary, 'G3');
    const g = await get(`/api/datasets/${id1}/groupby`, { by: 'school', metric: 'G3' }); assert.equal(g.body.groups.length, 2);
    assert.equal((await get(`/api/datasets/${id1}/groupby`, { by: 'khongco' })).code, 400);
    assert.equal((await get(`/api/datasets/${id1}/scatter`, { x: 'G1', y: 'school' })).code, 400);
    const sc = await get(`/api/datasets/${id1}/scatter`, { x: 'G1', y: 'G3' }); assert.ok(sc.body.r > 0.7);
    assert.equal((await get('/api/policies')).body.policies.length, 4);
  });
  await t('records: admin thấy hết, giáo viên chưa tập huấn bị che hoàn toàn', async () => {
    let r = await get(`/api/datasets/${id1}/records`, { role: 'admin', school: '*', limit: '15' });
    assert.equal(r.body.total, 395); assert.equal(r.body.rows.length, 15); assert.equal(r.body.summary.lockedCells, 0);
    assert.equal(Object.keys(r.body.rows[0].data).length, 33);
    r = await get(`/api/datasets/${id1}/records`, { role: 'teacher', school: 'GP', trained: 'false' });
    assert.equal(r.body.summary.visibleCells, 0); assert.ok(r.body.summary.lockedCells > 0);
  });
  await t('records: giáo viên đã tập huấn chỉ nhận trường academic, đúng trường học', async () => {
    const r = await get(`/api/datasets/${id1}/records`, { role: 'teacher', school: 'MS', trained: 'true', limit: '100' });
    assert.ok(r.body.total > 0 && r.body.total < 395);
    for (const row of r.body.rows) assert.ok(Object.keys(row.data).every((k) => acl.GROUPS.academic.includes(k)));
    assert.ok(!JSON.stringify(r.body.rows).includes('"Mjob"'), 'trường bị che không được rời server');
  });
  await t('records: tìm kiếm không dò được dữ liệu bị che', async () => {
    const guardian = rows[0].guardian;
    const admin = await get(`/api/datasets/${id1}/records`, { role: 'admin', school: '*', q: guardian });
    const teacher = await get(`/api/datasets/${id1}/records`, { role: 'teacher', school: rows[0].school, trained: 'true', q: guardian });
    assert.ok(admin.body.total > 0); assert.equal(teacher.body.total, 0);
  });
  await t('records: phân trang và vai trò counselor', async () => {
    const a = await get(`/api/datasets/${id1}/records`, { role: 'counselor', school: 'GP', page: '2', limit: '10' });
    assert.equal(a.body.page, 2); assert.equal(a.body.rows.length, 10);
    assert.ok(a.body.rows.every((r) => 'health' in r.data && !('Mjob' in r.data)));
    const over = await get(`/api/datasets/${id1}/records`, { role: 'admin', school: '*', page: '999', limit: '100' });
    assert.equal(over.body.page, over.body.pages);
  });
  await t('nhật ký audit được ghi vào "MongoDB"', async () => {
    await new Promise((r) => setTimeout(r, 20));
    const a = await get('/api/audit');
    assert.ok(a.body.length >= 5); assert.ok(a.body.every((x) => 'role' in x && 'lockedCells' in x));
  });
  await t('xoá dataset; ID sai -> 400; không tồn tại -> 404', async () => {
    assert.equal((await app.handle('DELETE', `/api/datasets/${id2}`)).code, 200);
    assert.equal((await get('/api/datasets')).body.length, 1);
    assert.equal((await get('/api/datasets/abc/stats')).code, 400);
    assert.equal((await get(`/api/datasets/${'a'.repeat(24)}/stats`)).code, 404);
  });

  console.log('liên kết notebook (chạy Python thật)');
  const nbk = require('../lib/notebook');
  await t('toCSV rồi đọc lại cho đúng dữ liệu', () => {
    const back = parseCSV(nbk.toCSV(rows, cols));
    assert.equal(back.length, rows.length); assert.deepEqual(back[7], rows[7]);
  });
  await t('info: Python, điều kiện cột, kết quả mẫu', async () => {
    const r = await get('/api/notebook/info', { datasetId: id1 });
    assert.equal(r.body.python.ok, true, JSON.stringify(r.body.python));
    assert.equal(r.body.eligible.ok, true); assert.equal(r.body.example, true);
  });
  await t('kết quả mẫu đi kèm: 40 cell, có ảnh và bảng', async () => {
    const r = await get('/api/notebook/result');
    assert.equal(r.body.cells.length, 40); assert.equal(r.body.meta.ok, true);
    const outs = r.body.cells.flatMap((c) => c.outputs || []);
    assert.ok(outs.some((o) => o.kind === 'image' && o.png.length > 1000)); assert.ok(outs.some((o) => o.kind === 'table'));
    assert.equal((await get('/api/notebook/download', { kind: 'source' })).body.download.endsWith('.ipynb'), true);
  });
  await t('dataset thiếu cột G1..G3 bị từ chối chạy notebook', async () => {
    const up = await app.handle('POST', '/api/datasets/upload', { file: { buffer: Buffer.from('a,b\n1,x\n2,y\n'), originalname: 'nho.csv' }, body: {} });
    const r = await app.handle('POST', '/api/notebook/run', { body: { datasetId: up.body.id } });
    assert.equal(r.code, 400); assert.match(r.body.error, /thiếu cột/);
    assert.equal((await app.handle('POST', '/api/notebook/run', { body: { datasetId: 'x' } })).code, 400);
    await app.handle('DELETE', `/api/datasets/${up.body.id}`);
  });
  await t('chạy notebook trên dataset trong MongoDB, thăm dò trạng thái, đọc kết quả', async () => {
    let r = await app.handle('POST', '/api/notebook/run', { body: { datasetId: id1 } });
    assert.equal(r.code, 202); const job = r.body.jobId;
    r = await app.handle('POST', '/api/notebook/run', { body: { datasetId: id1 } });
    assert.equal(r.code, 409, 'không cho chạy song song');
    let st; for (let i = 0; i < 120; i++) { st = (await get(`/api/notebook/jobs/${job}`)).body; if (st.status !== 'running') break; await new Promise((ok) => setTimeout(ok, 1000)); }
    assert.equal(st.status, 'done', JSON.stringify(st));
    const res = await get('/api/notebook/result', { jobId: job });
    assert.equal(res.body.meta.rows, 395); assert.match(res.body.meta.label, /Mẫu/);
    assert.equal(res.body.cells.filter((c) => c.type === 'code').length, 23);
    assert.ok(res.body.cells.flatMap((c) => c.outputs || []).filter((o) => o.kind === 'image').length >= 6);
    assert.equal((await get('/api/notebook/info', { datasetId: id1 })).body.latest.jobId, job);
    assert.ok((await get('/api/notebook/download', { jobId: job })).body.download.includes('executed'));
    assert.ok(!fs.existsSync(path.join(__dirname, '..', 'notebook', 'runs', job, 'data.csv')), 'CSV tạm phải bị xoá');
    assert.equal((await get('/api/notebook/jobs/zzzz')).code, 400);
  });
  for (const d of fs.readdirSync(path.join(__dirname, '..', 'notebook', 'runs'))) if (d !== '.gitkeep') fs.rmSync(path.join(__dirname, '..', 'notebook', 'runs', d), { recursive: true, force: true });

  console.log(`\n${pass} kiểm thử đạt${process.exitCode ? ', CÓ LỖI' : ''}`);
})();
