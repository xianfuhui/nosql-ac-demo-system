'use strict';
// Tải file từ link, có chống SSRF (chặn địa chỉ nội bộ, kiểm tra lại sau mỗi lần chuyển hướng) và giới hạn dung lượng.
const dns = require('dns').promises;
const net = require('net');
const { httpErr } = require('./errors');

const MAX_BYTES = 50 * 1024 * 1024;

function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const l = ip.toLowerCase();
  if (l === '::1' || l === '::') return true;
  if (l.startsWith('::ffff:')) {
    const v4 = l.slice(7);
    return net.isIPv4(v4) ? isPrivate(v4) : true;
  }
  return /^(fc|fd|fe8|fe9|fea|feb)/.test(l);
}

async function assertPublic(u) {
  if (!/^https?:$/.test(u.protocol)) throw httpErr(400, 'Chỉ hỗ trợ link http hoặc https');
  if (process.env.ALLOW_PRIVATE_URLS === '1') return;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  let addrs;
  try { addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true }); }
  catch { throw httpErr(400, 'Không phân giải được tên miền của link'); }
  if (!addrs.length || addrs.some((a) => isPrivate(a.address))) {
    throw httpErr(400, 'Không cho phép nhập từ địa chỉ nội bộ');
  }
}

// github.com/.../blob/... -> raw.githubusercontent.com/...
function normalize(u) {
  if (u.hostname === 'github.com') {
    const m = u.pathname.match(/^\/([^/]+)\/([^/]+)\/blob\/(.+)$/);
    if (m) return new URL(`https://raw.githubusercontent.com/${m[1]}/${m[2]}/${m[3]}`);
  }
  return u;
}

async function fetchBuffer(urlStr) {
  let u;
  try { u = normalize(new URL(urlStr)); } catch { throw httpErr(400, 'Link không hợp lệ'); }
  let res;
  for (let hop = 0; hop < 5; hop++) {
    await assertPublic(u);
    try {
      res = await fetch(u, { redirect: 'manual', signal: AbortSignal.timeout(30000), headers: { 'user-agent': 'so-diem/1.0' } });
    } catch { throw httpErr(502, 'Không tải được link (hết thời gian hoặc lỗi mạng)'); }
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      u = new URL(res.headers.get('location'), u);
      res = null;
      continue;
    }
    break;
  }
  if (!res) throw httpErr(400, 'Link chuyển hướng quá nhiều lần');
  if (!res.ok) throw httpErr(400, `Máy chủ của link trả về mã ${res.status}`);
  const declared = Number(res.headers.get('content-length') || 0);
  if (declared > MAX_BYTES) throw httpErr(413, 'File quá lớn (tối đa 50 MB)');

  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_BYTES) { await reader.cancel(); throw httpErr(413, 'File quá lớn (tối đa 50 MB)'); }
    chunks.push(value);
  }
  const filename = decodeURIComponent(u.pathname.split('/').filter(Boolean).pop() || 'download');
  return { buf: Buffer.concat(chunks), filename, finalUrl: u.toString() };
}

module.exports = { fetchBuffer, isPrivate };
