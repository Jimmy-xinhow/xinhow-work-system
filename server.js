'use strict';
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET;
const USERS = [
  { name: process.env.ADMIN_NAME || 'jimmy', pass: process.env.ADMIN_PASSWORD, role: 'admin' },
  { name: process.env.STAFF_NAME || 'mio', pass: process.env.STAFF_PASSWORD, role: 'staff' }
].filter(u => u.pass);
if (!SECRET || SECRET.length < 24) { console.error('SESSION_SECRET 必須設定且至少 24 字元'); process.exit(1); }
if (!USERS.some(u => u.role === 'admin')) { console.error('ADMIN_PASSWORD 必須設定'); process.exit(1); }
if (!process.env.DATABASE_URL) { console.error('DATABASE_URL 必須設定（在 Railway 加 Postgres 後會自動提供）'); process.exit(1); }

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'off' || /localhost|127\.0\.0\.1|\.railway\.internal/.test(process.env.DATABASE_URL) ? false : { rejectUnauthorized: false }
});

/* 存取規則：與原本 Artifact 版相同。admin＝管理者（楊濬騰），staff＝員工 */
const RULES = {
  fees: { read: 'admin', write: 'admin' }, bills: { read: 'admin', write: 'admin' },
  settings: { read: 'admin', write: 'admin' }, channels: { read: 'admin', write: 'admin' },
  plans: { read: 'admin', write: 'admin' },
  accept: { read: 'any', write: 'admin' }, sops: { read: 'any', write: 'admin' }, notify: { read: 'any', write: 'admin' }
};
const ruleOf = c => RULES[c] || { read: 'any', write: 'any' };
const can = (role, c, op) => ruleOf(c)[op] === 'any' || role === 'admin';
const COLL_RE = /^[A-Za-z0-9_-]{1,64}$/;
const ID_RE = /^[A-Za-z0-9_.:@+~-]{1,200}$/;

/* ---- 簽章 cookie ---- */
const b64 = b => Buffer.from(b).toString('base64url');
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
function makeToken(u) { const p = b64(JSON.stringify({ n: u.name, r: u.role, e: Date.now() + 30 * 864e5 })); return p + '.' + sign(p); }
function readToken(t) {
  if (!t) return null; const [p, s] = t.split('.'); if (!p || !s) return null;
  const a = Buffer.from(s), b = Buffer.from(sign(p)); if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.e > Date.now() ? { name: o.n, role: o.r } : null; } catch { return null; }
}
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(x => x.trim().split('=')).filter(x => x[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join('='))]));
const safeEq = (a, b) => { const x = crypto.createHash('sha256').update(String(a)).digest(), y = crypto.createHash('sha256').update(String(b)).digest(); return crypto.timingSafeEqual(x, y); };

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '5mb' }));
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'X-Frame-Options': 'DENY' });
  next();
});
app.use((req, res, next) => { req.user = readToken(cookies(req).sid); next(); });
const needAuth = (req, res, next) => req.user ? next() : res.status(401).json({ error: 'unauthorized' });
// 寫入只收 JSON，擋掉跨站表單送出
const needJson = (req, res, next) => (req.method === 'GET' || req.is('application/json')) ? next() : res.status(415).json({ error: 'json only' });

app.get('/health', (req, res) => res.send('ok'));

/* ---- 登入 ---- */
const tries = new Map();
app.post('/api/login', needJson, (req, res) => {
  const ip = req.ip, now = Date.now();
  const t = (tries.get(ip) || []).filter(x => now - x < 10 * 60e3);
  if (t.length >= 10) return res.status(429).json({ error: '嘗試次數太多，請 10 分鐘後再試' });
  const { name, password } = req.body || {};
  const u = USERS.find(x => safeEq(x.name, String(name || '').trim().toLowerCase()) && safeEq(x.pass, password || ''));
  if (!u) { t.push(now); tries.set(ip, t); return res.status(401).json({ error: '帳號或密碼錯誤' }); }
  const secure = req.secure ? '; Secure' : '';
  res.set('Set-Cookie', `sid=${encodeURIComponent(makeToken(u))}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${30 * 86400}${secure}`);
  res.json({ ok: true, role: u.role });
});
app.post('/api/logout', (req, res) => { res.set('Set-Cookie', 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); res.json({ ok: true }); });
app.get('/api/me', needAuth, (req, res) => res.json(req.user));

/* ---- 資料 ---- */
const sse = new Set();
function broadcast(coll) {
  for (const c of sse) if (can(c.role, coll, 'read')) c.res.write(`data: ${JSON.stringify({ coll })}\n\n`);
}
const guard = op => (req, res, next) => {
  const { coll, id } = req.params;
  if (!COLL_RE.test(coll) || (id !== undefined && !ID_RE.test(id))) return res.status(400).json({ error: 'bad path' });
  if (!can(req.user.role, coll, op)) return res.status(403).json({ error: 'forbidden' });
  next();
};
const newId = () => crypto.randomBytes(10).toString('hex');

app.get('/api/stream', needAuth, (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.flushHeaders(); res.write('retry: 3000\n\n');
  const c = { res, role: req.user.role }; sse.add(c);
  const hb = setInterval(() => res.write(': hb\n\n'), 25000);
  req.on('close', () => { clearInterval(hb); sse.delete(c); });
});

app.get('/api/c/:coll', needAuth, guard('read'), async (req, res) => {
  const r = await pool.query('SELECT id, data FROM docs WHERE coll=$1', [req.params.coll]);
  res.json(r.rows);
});
app.post('/api/c/:coll', needAuth, needJson, guard('write'), async (req, res) => {
  const id = newId();
  await pool.query('INSERT INTO docs(coll,id,data) VALUES($1,$2,$3)', [req.params.coll, id, req.body || {}]);
  broadcast(req.params.coll); res.json({ id });
});
app.put('/api/c/:coll/:id', needAuth, needJson, guard('write'), async (req, res) => {
  await pool.query(`INSERT INTO docs(coll,id,data) VALUES($1,$2,$3)
    ON CONFLICT (coll,id) DO UPDATE SET data=EXCLUDED.data, version=docs.version+1, updated_at=now()`, [req.params.coll, req.params.id, req.body || {}]);
  broadcast(req.params.coll); res.json({ ok: true });
});
app.patch('/api/c/:coll/:id', needAuth, needJson, guard('write'), async (req, res) => {
  const body = req.body || {}, del = Object.keys(body).filter(k => body[k] && body[k].__delete__ === true);
  const set = Object.fromEntries(Object.entries(body).filter(([k]) => !del.includes(k)));
  await pool.query(`INSERT INTO docs(coll,id,data) VALUES($1,$2,$3::jsonb)
    ON CONFLICT (coll,id) DO UPDATE SET data=(docs.data || $3::jsonb) - $4::text[], version=docs.version+1, updated_at=now()`,
    [req.params.coll, req.params.id, set, del]);
  broadcast(req.params.coll); res.json({ ok: true });
});
app.delete('/api/c/:coll/:id', needAuth, guard('write'), async (req, res) => {
  await pool.query('DELETE FROM docs WHERE coll=$1 AND id=$2', [req.params.coll, req.params.id]);
  broadcast(req.params.coll); res.json({ ok: true });
});

// 管理者備份：下載全部資料（JSON）
app.get('/api/export', needAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  const r = await pool.query('SELECT coll,id,data FROM docs ORDER BY coll,id');
  const out = {}; r.rows.forEach(x => { (out[x.coll] ||= {})[x.id] = x.data; });
  res.set('Content-Disposition', `attachment; filename="xinhow-backup-${new Date().toISOString().slice(0, 10)}.json"`);
  res.json(out);
});


// 管理者匯入／還原：把備份或初始資料（{集合:{文件ID:資料}}）寫入資料庫，同 ID 會覆蓋
app.post('/api/import', needAuth, needJson, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  const d = req.body;
  if (!d || typeof d !== 'object' || Array.isArray(d)) return res.status(400).json({ error: '格式不對' });
  const rows = [];
  for (const [coll, docs] of Object.entries(d)) {
    if (!COLL_RE.test(coll) || !docs || typeof docs !== 'object') return res.status(400).json({ error: '集合名稱不合法：' + coll });
    for (const [id, data] of Object.entries(docs)) {
      if (!ID_RE.test(id) || !data || typeof data !== 'object' || Array.isArray(data)) return res.status(400).json({ error: '文件不合法：' + coll + '/' + id });
      rows.push([coll, id, data]);
    }
  }
  if (rows.length > 20000) return res.status(400).json({ error: '筆數太多' });
  const cx = await pool.connect();
  try {
    await cx.query('BEGIN');
    for (const r of rows) await cx.query(`INSERT INTO docs(coll,id,data) VALUES($1,$2,$3)
      ON CONFLICT (coll,id) DO UPDATE SET data=EXCLUDED.data, version=docs.version+1, updated_at=now()`, r);
    await cx.query('COMMIT');
  } catch (e) { await cx.query('ROLLBACK'); throw e; } finally { cx.release(); }
  new Set(rows.map(r => r[0])).forEach(broadcast);
  res.json({ ok: true, count: rows.length });
});

/* ---- 頁面 ---- */
const pub = path.join(__dirname, 'public');
app.get('/login', (req, res) => req.user ? res.redirect('/') : res.sendFile(path.join(pub, 'login.html')));
app.get('/import', (req, res) => !req.user ? res.redirect('/login') : req.user.role !== 'admin' ? res.status(403).send('只有管理者可以匯入') : res.sendFile(path.join(pub, 'import.html')));
app.get('/shim.js', (req, res) => res.sendFile(path.join(pub, 'shim.js')));
app.get('/', (req, res) => req.user ? res.sendFile(path.join(pub, 'index.html')) : res.redirect('/login'));
app.use((req, res) => res.status(404).send('Not found'));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'server error' }); });

async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS docs(
    coll text NOT NULL, id text NOT NULL, data jsonb NOT NULL DEFAULT '{}'::jsonb,
    version int NOT NULL DEFAULT 1, updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(coll,id))`);
  app.listen(PORT, () => console.log('listening on ' + PORT));
}
init().catch(e => { console.error(e); process.exit(1); });
