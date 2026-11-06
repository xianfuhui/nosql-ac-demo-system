'use strict';
// Bản giả lập mongodb trong bộ nhớ (chỉ phần API mà server.js dùng).
const crypto = require('crypto');
class ObjectId {
  constructor(v) { this.v = v ? String(v) : crypto.randomBytes(12).toString('hex'); }
  toString() { return this.v; }
  static isValid(x) { return x instanceof ObjectId || (typeof x === 'string' && /^[0-9a-f]{24}$/.test(x)); }
}
const match = (d, f) => Object.keys(f).every((k) => String(d[k]) === String(f[k]));
class Cursor {
  constructor(arr) { this.a = arr; }
  sort(spec) { const [k, dir] = Object.entries(spec)[0]; this.a = [...this.a].sort((x, y) => (x[k] > y[k] ? 1 : x[k] < y[k] ? -1 : 0) * dir); return this; }
  limit(n) { this.a = this.a.slice(0, n); return this; }
  project(spec) { this.a = this.a.map((d) => { const o = {}; for (const k of Object.keys(spec)) o[k] = d[k]; return o; }); return this; }
  async toArray() { return this.a; }
}
class Collection {
  constructor() { this.docs = []; }
  async insertOne(d) { if (!d._id) d._id = new ObjectId(); this.docs.push(d); return { insertedId: d._id }; }
  async insertMany(ds) { for (const d of ds) await this.insertOne(d); return { insertedCount: ds.length }; }
  find(f = {}) { return new Cursor(this.docs.filter((d) => match(d, f))); }
  async findOne(f) { return this.docs.find((d) => match(d, f)) || null; }
  async deleteMany(f) { const n = this.docs.length; this.docs = this.docs.filter((d) => !match(d, f)); return { deletedCount: n - this.docs.length }; }
  async deleteOne(f) { const i = this.docs.findIndex((d) => match(d, f)); if (i >= 0) this.docs.splice(i, 1); return { deletedCount: i >= 0 ? 1 : 0 }; }
  async countDocuments() { return this.docs.length; }
  async createIndex() {}
}
class MongoClient {
  constructor() { this.cols = {}; }
  async connect() {}
  db() { return { collection: (n) => (this.cols[n] ||= new Collection()), command: async () => ({ ok: 1 }) }; }
}
module.exports = { MongoClient, ObjectId };
