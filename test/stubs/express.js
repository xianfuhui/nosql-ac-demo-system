'use strict';
// Bản giả lập express tối thiểu để kiểm thử logic route khi chưa cài được package thật.
function express() {
  const routes = []; let errorHandler = null;
  const add = (method) => (p, ...hs) => routes.push({ method, p, hs });
  const app = {
    disable() {}, use(...a) { const f = a[a.length - 1]; if (typeof f === 'function' && f.length === 4) errorHandler = f; else if (typeof a[0] === 'string' && a.length === 2) routes.push({ method: 'USE', p: a[0], hs: [f] }); },
    get: add('GET'), post: add('POST'), delete: add('DELETE'), listen(port, cb) { cb && cb(); },
    async handle(method, url, { query = {}, body = {}, file = null } = {}) {
      const res = { code: 200, body: null, status(c) { this.code = c; return this; }, json(b) { this.body = b; return this; }, send(b) { this.body = b; return this; }, sendFile() { return this; }, download(f, n) { this.body = { download: n, file: f }; return this; }, end() { return this; } };
      const req = { method, query, body, file, params: {} };
      let route = null;
      for (const r of routes) {
        if (r.method === 'USE') { if (url.startsWith(r.p)) { route = r; break; } continue; }
        if (r.method !== method) continue;
        const names = []; const re = new RegExp('^' + r.p.replace(/:([a-z]+)/gi, (_, n) => { names.push(n); return '([^/]+)'; }) + '$');
        const m = re.exec(url);
        if (m) { names.forEach((n, i) => { req.params[n] = m[i + 1]; }); route = r; break; }
      }
      try {
        if (!route) throw Object.assign(new Error('no route'), { status: 404 });
        for (const h of route.hs) {
          await new Promise((ok, bad) => { const r = h(req, res, (e) => (e ? bad(e) : ok())); if (r && r.then) r.then(() => ok(), bad); else if (h.length < 3) ok(); });
          if (res.body !== null) break;
        }
      } catch (e) { errorHandler(e, req, res, () => {}); }
      return res;
    },
  };
  return app;
}
express.json = () => (q, s, n) => n(); express.static = () => (q, s, n) => n();
module.exports = express;
