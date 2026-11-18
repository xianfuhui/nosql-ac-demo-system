// Kho dữ liệu RIÊNG của hệ thống. Địa chỉ nhập ngay trên giao diện (Nạp dữ liệu → "Database hệ thống") hoặc đặt MONGO_URI trong .env.
// Hỗ trợ đủ 4 kiểu NoSQL, nhận diện theo đầu link:
//   mongodb://… (Document) · redis://… (Key-value) · cassandra://…/keyspace (Wide-column) · neo4j://… hoặc bolt://… (Graph)
// Mọi dữ liệu đã nạp được sao chép vào đây, rồi hệ thống đọc lại từ chính DB này để phân tích và benchmark.
//
// Dữ liệu 1 bộ = các "phần" (collection / table / nodes / edges…). Mỗi phần là danh sách dòng { _i, _k?, _v }:
//   array -> _v là phần tử · object -> _k là khóa, _v là giá trị · scalar -> 1 dòng _v.
//   Mongo   : collection _datasets (siêu dữ liệu) + ds_<tên>__<phần>; _v lưu nguyên dạng BSON.
//   Redis   : acl:ds:<tên>:__meta (JSON) + list acl:ds:<tên>:<phần> (mỗi phần tử là 1 dòng JSON).
//   Cassandra: bảng acl_meta, acl_rows (keyspace trong link phải tồn tại sẵn; bảng tự tạo); _v là JSON.
//   Neo4j   : node (:AclDataset {name, meta}) và (:AclRow {ds, part, i, k, v}); v là JSON.
'use strict';
const ENV_URI = process.env.MONGO_URI || '';
const LOAD_LIMIT = 10000, CHUNK = 1000;
const kindOf = u => /^mongodb(\+srv)?:\/\//.test(u) ? 'mongo' : /^rediss?:\/\//.test(u) ? 'redis' : /^cassandra:\/\//.test(u) ? 'cassandra' : /^(neo4j|bolt)(\+s|\+ssc)?:\/\//.test(u) ? 'neo4j' : null;
const first = e => String(e && e.message || e).split('\n')[0].slice(0, 250);
const dec = s => decodeURIComponent(s);
const chunks = (a, n = CHUNK) => Array.from({ length: Math.ceil(a.length / n) }, (_, i) => a.slice(i * n, (i + 1) * n));
const safe = s => String(s).replace(/[^\w-]/g, '_').slice(0, 40) || '_';
const plain = v => v !== null && typeof v === 'object' && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);
const shapeOf = v => Array.isArray(v) ? 'array' : plain(v) ? 'object' : 'scalar';
// Tên trường lồng bắt đầu bằng "$" hoặc chứa "." bị đổi để mọi phiên bản MongoDB nhận; "__proto__" bị bỏ.
const fix = (v, d = 0) => {
  if (d > 30) return null;
  if (Array.isArray(v)) return v.map(x => fix(x, d + 1));
  if (!plain(v)) return v === undefined ? null : v;
  const o = {};
  for (const [k, x] of Object.entries(v)) if (k !== '__proto__') o[k.replace(/^\$/, '_$').replace(/\./g, '_')] = fix(x, d + 1);
  return o;
};

// ---- chia dữ liệu thành các phần và ghép lại ----
function plan(data) {
  if (data === null || typeof data !== 'object') throw new Error('Dữ liệu phải là object hoặc mảng JSON');
  const isArr = Array.isArray(data), T = isArr ? { rows: data } : data;
  return { shape: isArr ? 'array' : 'object', parts: Object.entries(T).filter(([p]) => p !== '__proto__').map(([part, val]) => {
    const shape = shapeOf(val);
    return { part, shape, rows: shape === 'array' ? val.map((v, i) => ({ _i: i, _v: fix(v) }))
      : shape === 'object' ? Object.entries(val).filter(([k]) => k !== '__proto__').map(([k, v], i) => ({ _i: i, _k: k, _v: fix(v) }))
      : [{ _i: 0, _v: fix(val) }] };
  }) };
}
function assemble(shape, parts) {   // parts: { phần: { shape, rows } }
  const T = {};
  for (const [part, p] of Object.entries(parts)) T[part] = p.shape === 'array' ? p.rows.map(x => x._v) : p.shape === 'object' ? Object.fromEntries(p.rows.map(x => [x._k, x._v])) : p.rows[0] ? p.rows[0]._v : null;
  return shape === 'array' ? T.rows : T;
}
const metaOf = (name, pl, refs) => ({ shape: pl.shape, parts: Object.fromEntries(pl.parts.map(p => [p.part, { ref: refs[p.part], shape: p.shape, n: p.rows.length }])) });

// ---- Mongo ----
function makeMongo(getDb, label, closeFn) {
  const META = '_datasets';
  return { kind: 'mongo', db: label, close: closeFn || (async () => {}),
    async del(name) {
      const d = await getDb(), m = await d.collection(META).findOne({ _id: name }); if (!m) return;
      for (const p of Object.values(m.parts || {})) await d.collection(p.ref).drop().catch(() => {});
      await d.collection(META).deleteOne({ _id: name });
    },
    async put(name, pl, info) {
      const d = await getDb(), used = new Set(), refs = {}; await this.del(name);
      try {
        for (const p of pl.parts) {
          let c = `ds_${safe(name)}__${safe(p.part)}`; while (used.has(c)) c += '_'; used.add(c); refs[p.part] = c;
          for (const ch of chunks(p.rows)) await d.collection(c).insertMany(ch, { ordered: true });
        }
        await d.collection(META).replaceOne({ _id: name }, { _id: name, ...metaOf(name, pl, refs), ...info, loadedAt: new Date() }, { upsert: true });
      } catch (e) { for (const c of Object.values(refs)) await d.collection(c).drop().catch(() => {}); throw e; }
      return refs;
    },
    async get(name) {
      const d = await getDb(), m = await d.collection(META).findOne({ _id: name }); if (!m) return null;
      const parts = {};
      for (const [part, p] of Object.entries(m.parts)) parts[part] = { shape: p.shape, rows: await d.collection(p.ref).find({}).sort({ _i: 1 }).limit(LOAD_LIMIT).toArray() };
      return { shape: m.shape, parts };
    },
    async probe(name, part, ref) { return (await getDb()).collection(ref || part).findOne({}); } };
}
function openMongo(uri) {
  const { MongoClient } = require('mongodb'), c = new MongoClient(uri, { serverSelectionTimeoutMS: 5000 }),
    dbn = (uri.match(/^mongodb(?:\+srv)?:\/\/[^/]+\/([^?]*)/) || [])[1] || 'nosql_acl';
  const p = c.connect().then(() => c.db(dbn)); p.catch(() => {});
  return makeMongo(() => p, dbn, () => c.close());
}

// ---- Redis ----
function openRedis(uri) {
  const { createClient } = require('redis'), c = createClient({ url: uri, socket: { connectTimeout: 5000, reconnectStrategy: false } }); c.on('error', () => {});
  const ready = c.connect().then(() => c); ready.catch(() => {});
  const mk = n => `acl:ds:${n}:__meta`, pk = (n, p) => `acl:ds:${n}:${p}`;
  return { kind: 'redis', db: 'redis', close: async () => { await c.quit().catch(() => {}); },
    async del(name) {
      await ready; const raw = await c.get(mk(name)); if (!raw) return;
      for (const p of Object.values(JSON.parse(raw).parts)) await c.del(p.ref);
      await c.del(mk(name));
    },
    async put(name, pl, info) {
      await ready; await this.del(name); const refs = {};
      try {
        for (const p of pl.parts) { refs[p.part] = pk(name, p.part); for (const ch of chunks(p.rows)) await c.rPush(refs[p.part], ch.map(r => JSON.stringify(r))); }
        await c.set(mk(name), JSON.stringify({ ...metaOf(name, pl, refs), ...info, loadedAt: new Date().toISOString() }));
      } catch (e) { for (const k of Object.values(refs)) await c.del(k).catch(() => {}); throw e; }
      return refs;
    },
    async get(name) {
      await ready; const raw = await c.get(mk(name)); if (!raw) return null; const m = JSON.parse(raw), parts = {};
      for (const [part, p] of Object.entries(m.parts)) parts[part] = { shape: p.shape, rows: (await c.lRange(p.ref, 0, LOAD_LIMIT - 1)).map(x => JSON.parse(x)) };
      return { shape: m.shape, parts };
    },
    async probe(name, part, ref) { await ready; return c.lIndex(ref || pk(name, part), 0); } };
}

// ---- Cassandra ----
function openCassandra(uri) {
  const { Client, auth, concurrent } = require('cassandra-driver'), u = new URL(uri), ks = dec(u.pathname.slice(1));
  if (!/^\w+$/.test(ks)) throw new Error('Thiếu hoặc sai keyspace. Ví dụ: cassandra://host:9042/my_keyspace');
  const c = new Client({ contactPoints: [`${u.hostname}:${u.port || 9042}`], localDataCenter: u.searchParams.get('dc') || 'datacenter1', keyspace: ks,
    ...(u.username ? { authProvider: new auth.PlainTextAuthProvider(dec(u.username), dec(u.password)) } : {}), socketOptions: { connectTimeout: 5000, readTimeout: 8000 } });
  const ready = (async () => {
    await Promise.race([c.connect(), new Promise((_, j) => setTimeout(() => j(new Error('Không kết nối được Cassandra (timeout). Keyspace phải tồn tại sẵn.')), 9000))]);
    await c.execute('CREATE TABLE IF NOT EXISTS acl_meta (name text PRIMARY KEY, meta text)');
    await c.execute('CREATE TABLE IF NOT EXISTS acl_rows (ds text, part text, i int, k text, v text, PRIMARY KEY ((ds, part), i))');
  })(); ready.catch(() => {});
  const q = (s, p) => c.execute(s, p, { prepare: true });
  return { kind: 'cassandra', db: ks, close: async () => { await c.shutdown().catch(() => {}); },
    async del(name) {
      await ready; const r = await q('SELECT meta FROM acl_meta WHERE name = ?', [name]); if (!r.rows.length) return;
      for (const part of Object.keys(JSON.parse(r.rows[0].meta).parts)) await q('DELETE FROM acl_rows WHERE ds = ? AND part = ?', [name, part]);
      await q('DELETE FROM acl_meta WHERE name = ?', [name]);
    },
    async put(name, pl, info) {
      await ready; await this.del(name); const refs = {};
      try {
        for (const p of pl.parts) {
          refs[p.part] = p.part;
          await concurrent.executeConcurrent(c, 'INSERT INTO acl_rows (ds, part, i, k, v) VALUES (?, ?, ?, ?, ?)',
            p.rows.map(r => [name, p.part, r._i, r._k == null ? null : String(r._k), JSON.stringify(r._v)]), { prepare: true, concurrencyLevel: 32, raiseOnFirstError: true });
        }
        await q('INSERT INTO acl_meta (name, meta) VALUES (?, ?)', [name, JSON.stringify({ ...metaOf(name, pl, refs), ...info, loadedAt: new Date().toISOString() })]);
      } catch (e) { for (const part of Object.keys(refs)) await q('DELETE FROM acl_rows WHERE ds = ? AND part = ?', [name, part]).catch(() => {}); throw e; }
      return refs;
    },
    async get(name) {
      await ready; const r = await q('SELECT meta FROM acl_meta WHERE name = ?', [name]); if (!r.rows.length) return null; const m = JSON.parse(r.rows[0].meta), parts = {};
      for (const [part, p] of Object.entries(m.parts)) {
        const rs = await c.execute(`SELECT i, k, v FROM acl_rows WHERE ds = ? AND part = ? LIMIT ${LOAD_LIMIT}`, [name, part], { prepare: true });
        parts[part] = { shape: p.shape, rows: rs.rows.map(x => ({ _i: x.i, ...(x.k != null ? { _k: x.k } : {}), _v: JSON.parse(x.v) })) };
      }
      return { shape: m.shape, parts };
    },
    async probe(name, part) { await ready; return q('SELECT v FROM acl_rows WHERE ds = ? AND part = ? LIMIT 1', [name, part]); } };
}

// ---- Neo4j ----
function openNeo4j(uri) {
  const neo = require('neo4j-driver'), u = new URL(uri), db = dec(u.pathname.slice(1)) || undefined;
  const d = neo.driver(`${u.protocol}//${u.host}`, neo.auth.basic(dec(u.username), dec(u.password)), { connectionTimeout: 5000, maxTransactionRetryTime: 8000 });
  const ready = d.getServerInfo(); ready.catch(() => {});
  const run = async (cy, p, w = true) => { await ready; const s = d.session({ database: db, defaultAccessMode: w ? neo.session.WRITE : neo.session.READ }); try { return await s.run(cy, p); } finally { await s.close().catch(() => {}); } };
  return { kind: 'neo4j', db: db || u.hostname, close: async () => { await d.close().catch(() => {}); },
    async del(name) { await run('MATCH (r:AclRow {ds: $n}) DETACH DELETE r', { n: name }); await run('MATCH (m:AclDataset {name: $n}) DETACH DELETE m', { n: name }); },
    async put(name, pl, info) {
      await this.del(name); const refs = {};
      try {
        for (const p of pl.parts) {
          refs[p.part] = p.part;
          for (const ch of chunks(p.rows)) await run('UNWIND $rows AS r CREATE (:AclRow {ds: $n, part: $p, i: r.i, k: r.k, v: r.v})',
            { n: name, p: p.part, rows: ch.map(r => ({ i: neo.int(r._i), k: r._k == null ? null : String(r._k), v: JSON.stringify(r._v) })) });
        }
        await run('CREATE (:AclDataset {name: $n, meta: $m})', { n: name, m: JSON.stringify({ ...metaOf(name, pl, refs), ...info, loadedAt: new Date().toISOString() }) });
      } catch (e) { await this.del(name).catch(() => {}); throw e; }
      return refs;
    },
    async get(name) {
      const r = await run('MATCH (m:AclDataset {name: $n}) RETURN m.meta AS m', { n: name }, false); if (!r.records.length) return null;
      const m = JSON.parse(r.records[0].get('m')), parts = {};
      for (const [part, p] of Object.entries(m.parts)) {
        const rs = await run('MATCH (r:AclRow {ds: $n, part: $p}) RETURN r.i AS i, r.k AS k, r.v AS v ORDER BY r.i LIMIT $l', { n: name, p: part, l: neo.int(LOAD_LIMIT) }, false);
        parts[part] = { shape: p.shape, rows: rs.records.map(x => ({ _i: neo.integer.toNumber(x.get('i')), ...(x.get('k') != null ? { _k: x.get('k') } : {}), _v: JSON.parse(x.get('v')) })) };
      }
      return { shape: m.shape, parts };
    },
    async probe(name, part) { return run('MATCH (r:AclRow {ds: $n, part: $p}) RETURN r LIMIT 1', { n: name, p: part }, false); } };
}
const OPEN = { mongo: openMongo, redis: openRedis, cassandra: openCassandra, neo4j: openNeo4j };

// ---- cấu hình hiện tại (chỉ trong bộ nhớ, không ghi state.json vì link chứa mật khẩu) ----
let cur = ENV_URI ? { uri: ENV_URI, src: 'env' } : null, be = null;
const enabled = () => !!cur;
function backend() {
  if (!cur) throw new Error('Chưa có database hệ thống. Nhập link ở tab Nạp dữ liệu → "Database hệ thống" hoặc đặt MONGO_URI trong .env');
  if (!be) {
    const k = kindOf(cur.uri);
    if (!k) throw new Error('Link database hệ thống phải bắt đầu bằng mongodb:// · redis:// · cassandra:// · neo4j:// (hoặc bolt://)');
    be = OPEN[k](cur.uri);
  }
  return be;
}
const wrap = async fn => { try { return await fn(backend()); } catch (e) { throw new Error('Database hệ thống: ' + first(e)); } };

// Đặt link mới: kết nối thử (ghi/đọc được mới nhận). Lỗi thì giữ nguyên cấu hình cũ.
async function configure(uri, src = 'ui') {
  uri = String(uri || '').trim();
  const k = kindOf(uri); if (!k) throw new Error('Link phải bắt đầu bằng mongodb:// · redis:// · cassandra:// · neo4j:// (hoặc bolt://)');
  let nb; try { nb = OPEN[k](uri); await nb.get('__probe__'); } catch (e) { if (nb) await nb.close().catch(() => {}); throw new Error('Không kết nối được database hệ thống: ' + first(e)); }
  const old = be; cur = { uri, src }; be = nb; if (old) await old.close().catch(() => {});
  return info();
}
async function reset() { const old = be; be = null; cur = ENV_URI ? { uri: ENV_URI, src: 'env' } : null; if (old) await old.close().catch(() => {}); return info(); }
const info = () => cur ? { kind: kindOf(cur.uri) || '', db: be ? be.db : '', src: cur.src } : null;

async function save(name, data, extra = {}) {
  const pl = plan(data);
  return wrap(async b => { const refs = await b.put(name, pl, extra); return { kind: b.kind, db: b.db, parts: Object.fromEntries(pl.parts.map(p => [p.part, { ref: refs[p.part], n: p.rows.length }])) }; });
}
async function load(name) {
  return wrap(async b => { const g = await b.get(name); if (!g) throw new Error(`không tìm thấy bộ dữ liệu "${name}"`); return { data: assemble(g.shape, g.parts) }; });
}
const probe = (name, part, ref) => wrap(b => b.probe(name, part, ref));

module.exports = { enabled, configure, reset, info, save, load, probe, kindOf, close: async () => { if (be) await be.close(); },
  _test: { plan, assemble, makeMongo, use: b => { be = b; cur = { uri: 'test://', src: 'test' }; } } };
