/* Tactics HAT online sunucusu — bağımlılıksız (sadece Node.js 18+). */
'use strict';
const http = require('http');
const crypto = require('crypto');

const PORT = +process.env.PORT || 8080;
const MAX_ROOMS = +process.env.MAX_ROOMS || 500;
const MAX_PER_IP = +process.env.MAX_PER_IP || 24;
const EMPTY_GRACE_MS = 30000;
const MAX_FRAME = 16384;
const MAX_QUEUE = 32768;
const MSG_RATE = 120;
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

const rooms = new Map();
const ipCount = new Map();
let nextId = 1;

const CORS = { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' };

const server = http.createServer((req, res) => {
  const u = req.url.split('?')[0];
  if (u === '/ping') { res.writeHead(200, { ...CORS, 'Content-Type': 'text/plain' }); return res.end('ok'); }
  if (u === '/rooms') {
    const a = [];
    for (const r of rooms.values()) if (r.pub && r.clients.size) a.push({ c: r.code, n: r.name, p: r.clients.size, m: r.max });
    res.writeHead(200, { ...CORS, 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(a));
  }
  res.writeHead(200, { ...CORS, 'Content-Type': 'text/plain' });
  res.end('Tactics HAT online sunucusu · oda: ' + rooms.size);
});
server.keepAliveTimeout = 5000;

function frame(op, payload) {
  const len = payload.length;
  let h;
  if (len < 126) { h = Buffer.allocUnsafe(2); h[1] = len; }
  else if (len < 65536) { h = Buffer.allocUnsafe(4); h[1] = 126; h.writeUInt16BE(len, 2); }
  else { h = Buffer.allocUnsafe(10); h[1] = 127; h.writeBigUInt64BE(BigInt(len), 2); }
  h[0] = 0x80 | op;
  return Buffer.concat([h, payload]);
}
const textFrame = (s) => frame(1, Buffer.from(s));

function send(c, data, droppable) {
  const s = c.socket;
  if (s.destroyed || !s.writable) return;
  if (droppable && s.writableLength > MAX_QUEUE) return;
  s.write(data);
}

function closeClient(c, code) {
  try { c.socket.end(frame(8, Buffer.from([(code >> 8) & 255, code & 255]))); } catch (e) {}
  setTimeout(() => { try { c.socket.destroy(); } catch (e) {} }, 500);
}

function onUpgrade(req, socket) {
  const key = req.headers['sec-websocket-key'];
  if (!key || (req.headers.upgrade || '').toLowerCase() !== 'websocket') { socket.destroy(); return; }
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').toString().split(',')[0].trim();
  const n = (ipCount.get(ip) || 0) + 1;
  if (n > MAX_PER_IP) { socket.write('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n'); socket.destroy(); return; }
  ipCount.set(ip, n);

  const accept = crypto.createHash('sha1').update(key + GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.setNoDelay(true);
  socket.setKeepAlive(true, 15000);

  const q = new URL(req.url, 'http://x').searchParams;
  const code = String(q.get('room') || '').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 16);
  const c = { id: 'p' + (nextId++).toString(36), socket, room: null, alive: true, buf: Buffer.alloc(0), tokens: MSG_RATE, ip };
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return; cleaned = true;
    ipCount.set(ip, Math.max(0, (ipCount.get(ip) || 1) - 1));
    leave(c);
  };
  socket.on('close', cleanup); socket.on('error', cleanup); socket.on('end', cleanup);

  let r = code ? rooms.get(code) : null;
  if (!code) { send(c, textFrame('{"t":"x","e":"none"}')); return closeClient(c, 1000); }
  if (!r) {
    if (q.get('new') !== '1' || rooms.size >= MAX_ROOMS) { send(c, textFrame('{"t":"x","e":"none"}')); return closeClient(c, 1000); }
    const max = Math.min(16, Math.max(2, parseInt(q.get('max'), 10) || 8));
    r = { code, name: String(q.get('name') || code).replace(/[<>&"'`]/g, '').slice(0, 20), pub: q.get('pub') === '1', max, clients: new Map(), snap: new Map(), empty: null };
    rooms.set(code, r);
  }
  if (r.clients.size >= r.max) { send(c, textFrame('{"t":"x","e":"full"}')); return closeClient(c, 1000); }
  clearTimeout(r.empty);
  c.room = r; r.clients.set(c.id, c);
  const s = {}; for (const [k, v] of r.snap) s[k] = v;
  send(c, textFrame(JSON.stringify({ t: 'w', id: c.id, s })));

  socket.on('data', (d) => {
    c.buf = c.buf.length ? Buffer.concat([c.buf, d]) : d;
    try { parse(c); } catch (e) { socket.destroy(); }
  });
}

function parse(c) {
  for (;;) {
    const b = c.buf;
    if (b.length < 2) return;
    const op = b[0] & 15, masked = (b[1] & 128) !== 0;
    let len = b[1] & 127, off = 2;
    if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
    else if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); off = 10; }
    if (len > MAX_FRAME) { c.socket.destroy(); return; }
    if (!masked) { c.socket.destroy(); return; }
    if (b.length < off + 4 + len) return;
    const mask = b.subarray(off, off + 4), data = Buffer.allocUnsafe(len);
    for (let i = 0; i < len; i++) data[i] = b[off + 4 + i] ^ mask[i & 3];
    c.buf = b.subarray(off + 4 + len);
    if (op === 8) { closeClient(c, 1000); return; }
    if (op === 9) { send(c, frame(10, data)); continue; }
    if (op === 10) { c.alive = true; continue; }
    if (op === 1) message(c, data.toString('utf8'));
  }
}

setInterval(() => { for (const r of rooms.values()) for (const c of r.clients.values()) c.tokens = MSG_RATE; }, 1000);

function message(c, txt) {
  c.alive = true;
  if (--c.tokens < 0) return;
  let m; try { m = JSON.parse(txt); } catch (e) { return; }
  if (!m || typeof m !== 'object') return;
  if (m.t === 'g') { send(c, textFrame('{"t":"G","ts":' + (+m.ts || 0) + '}')); return; }
  if (m.t === 'p' && m.d && typeof m.d === 'object' && c.room) {
    c.room.snap.set(c.id, m.d);
    const out = textFrame(JSON.stringify({ t: 'u', i: c.id, d: m.d }));
    for (const o of c.room.clients.values()) if (o !== c) send(o, out, true);
  }
}

function leave(c) {
  const r = c.room; if (!r) return;
  c.room = null;
  r.clients.delete(c.id); r.snap.delete(c.id);
  const out = textFrame(JSON.stringify({ t: 'l', i: c.id }));
  for (const o of r.clients.values()) send(o, out);
  if (!r.clients.size) r.empty = setTimeout(() => { if (!r.clients.size) rooms.delete(r.code); }, EMPTY_GRACE_MS);
}

setInterval(() => {
  for (const r of rooms.values()) for (const c of r.clients.values()) {
    if (!c.alive) { c.socket.destroy(); continue; }
    c.alive = false; send(c, frame(9, Buffer.alloc(0)));
  }
}, 20000);

server.on('upgrade', onUpgrade);
if (require.main === module) server.listen(PORT, () => console.log('Tactics HAT sunucusu :' + PORT));
module.exports = { server, rooms };
