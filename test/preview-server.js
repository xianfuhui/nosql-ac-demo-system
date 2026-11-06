'use strict';
// Xem thử giao diện không cần MongoDB/npm: bọc app giả lập bằng HTTP thật. Chart.js được thay bằng bản rỗng.
const http = require('http'), fs = require('fs'), path = require('path'), Module = require('module');
const orig = Module._resolveFilename;
Module._resolveFilename = function (r, ...a) { return ['express', 'multer', 'mongodb'].includes(r) ? path.join(__dirname, 'stubs', r + '.js') : orig.call(this, r, ...a); };
const { app, start } = require('../server');
const pub = path.join(__dirname, '..', 'public');
const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript' };
(async () => {
  await start();
  const csv = fs.readFileSync(path.join(__dirname, '..', 'sample', 'sample-synthetic-students.csv'));
  await app.handle('POST', '/api/datasets/upload', { file: { buffer: csv, originalname: 'sample.csv' }, body: { name: 'Mẫu tổng hợp' } });
  http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/vendor/chart.js') { res.setHeader('content-type', 'text/javascript'); return res.end('window.Chart=class{constructor(){} destroy(){}};Chart.defaults={font:{}};'); }
    if (u.pathname.startsWith('/api/')) {
      let body = {};
      if (req.method === 'POST') { const ch = []; for await (const c of req) ch.push(c); try { body = JSON.parse(Buffer.concat(ch).toString() || '{}'); } catch { body = {}; } }
      const r = await app.handle(req.method, u.pathname, { query: Object.fromEntries(u.searchParams), body });
      res.statusCode = r.code; res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify(r.body));
    }
    const f = path.join(pub, u.pathname === '/' ? 'index.html' : u.pathname);
    if (!f.startsWith(pub) || !fs.existsSync(f)) { res.statusCode = 404; return res.end(); }
    res.setHeader('content-type', types[path.extname(f)] || 'text/plain'); res.end(fs.readFileSync(f));
  }).listen(3111, () => console.log('preview on 3111'));
})();
