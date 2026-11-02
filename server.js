'use strict';
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET;
if (!SECRET || SECRET.length < 24) { console.error('SESSION_SECRET 必須設定且至少 24 字元'); process.exit(1); }
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

/* ---- 密碼雜湊（scrypt）---- */
const scrypt = (pw, salt) => new Promise((ok, no) => crypto.scrypt(pw, salt, 64, (e, k) => e ? no(e) : ok(k)));
async function hashPw(pw) { const salt = crypto.randomBytes(16); return 's1$' + salt.toString('base64') + '$' + (await scrypt(pw, salt)).toString('base64'); }
async function checkPw(pw, stored) {
  const [v, s, h] = String(stored || '').split('$'); if (v !== 's1' || !s || !h) return false;
  const want = Buffer.from(h, 'base64'), got = await scrypt(String(pw), Buffer.from(s, 'base64'));
  return want.length === got.length && crypto.timingSafeEqual(want, got);
}
const DUMMY = 's1$' + Buffer.alloc(16).toString('base64') + '$' + Buffer.alloc(64).toString('base64');
const NAME_RE = /^[a-z0-9._-]{2,32}$/;
function pwProblem(pw, name, cur) {
  if (typeof pw !== 'string' || pw.length < 10) return '密碼至少 10 個字元';
  if (pw.length > 200) return '密碼太長';
  if (name && pw.toLowerCase().includes(name)) return '密碼不能包含帳號';
  if (cur !== undefined && pw === cur) return '新密碼不能和目前的密碼一樣';
  if (/^(.)\1+$/.test(pw)) return '密碼不能全部是同一個字';
  return null;
}

/* ---- 簽章 cookie（只放帳號與密碼版本，角色每次從資料庫查）---- */
const b64 = b => Buffer.from(b).toString('base64url');
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
function makeToken(u) { const p = b64(JSON.stringify({ n: u.name, v: u.sv, e: Date.now() + 30 * 864e5 })); return p + '.' + sign(p); }
function readToken(t) {
  if (!t) return null; const [p, s] = t.split('.'); if (!p || !s) return null;
  const a = Buffer.from(s), b = Buffer.from(sign(p)); if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.e > Date.now() ? { name: o.n, sv: o.v } : null; } catch { return null; }
}
const cookieStr = (req, u) => `sid=${encodeURIComponent(makeToken(u))}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${30 * 86400}${req.secure ? '; Secure' : ''}`;
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(x => x.trim().split('=')).filter(x => x[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join('='))]));

const getUser = async name => (await pool.query('SELECT name,display,role,pass_hash,must_change,disabled,sv,created_at,last_login FROM users WHERE name=$1', [name])).rows[0];
const pubUser = u => ({ name: u.name, display: u.display, role: u.role, mustChange: u.must_change });

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '5mb' }));
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'X-Frame-Options': 'DENY', 'Cache-Control': 'no-store' });
  next();
});
app.use(async (req, res, next) => {
  req.user = null;
  const t = readToken(cookies(req).sid);
  if (t) {
    const u = await getUser(t.name);
    if (u && !u.disabled && u.sv === t.sv) req.user = pubUser(u);
  }
  next();
});
const needAuth = (req, res, next) => req.user ? next() : res.status(401).json({ error: 'unauthorized' });
// 還沒改掉初始密碼的人，除了改密碼以外什麼都不能做
const needReady = (req, res, next) => !req.user ? res.status(401).json({ error: 'unauthorized' }) : req.user.mustChange ? res.status(403).json({ error: 'must_change_password' }) : next();
const needAdmin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'forbidden' });
// 寫入只收 JSON，擋掉跨站表單送出
const needJson = (req, res, next) => (req.method === 'GET' || req.is('application/json')) ? next() : res.status(415).json({ error: 'json only' });

app.get('/health', (req, res) => res.send('ok'));

/* ---- 登入／登出／改密碼 ---- */
const tries = new Map();
const limited = (key, max = 10) => { const now = Date.now(), t = (tries.get(key) || []).filter(x => now - x < 10 * 60e3); tries.set(key, t); return t.length >= max; };
const fail = key => { const t = tries.get(key) || []; t.push(Date.now()); tries.set(key, t); };
setInterval(() => { const now = Date.now(); for (const [k, v] of tries) if (!v.some(x => now - x < 10 * 60e3)) tries.delete(k); }, 10 * 60e3).unref();

app.post('/api/login', needJson, async (req, res) => {
  const ip = 'ip:' + req.ip;
  if (limited(ip)) return res.status(429).json({ error: '嘗試次數太多，請 10 分鐘後再試' });
  const name = String((req.body || {}).name || '').trim().toLowerCase(), password = String((req.body || {}).password || '');
  const u = NAME_RE.test(name) ? await getUser(name) : null;
  const ok = await checkPw(password, u ? u.pass_hash : DUMMY);   // 帳號不存在也跑一次雜湊，避免從回應時間猜帳號
  if (!u || !ok || u.disabled) { fail(ip); return res.status(401).json({ error: '帳號或密碼錯誤' }); }
  await pool.query('UPDATE users SET last_login=now() WHERE name=$1', [name]);
  res.set('Set-Cookie', cookieStr(req, u));
  res.json({ ok: true, role: u.role, mustChange: u.must_change });
});
app.post('/api/logout', (req, res) => { res.set('Set-Cookie', 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); res.json({ ok: true }); });
app.get('/api/me', needAuth, (req, res) => res.json(req.user));

app.post('/api/password', needAuth, needJson, async (req, res) => {
  const key = 'pw:' + req.user.name;
  if (limited(key)) return res.status(429).json({ error: '嘗試次數太多，請 10 分鐘後再試' });
  const cur = String((req.body || {}).current || ''), next = (req.body || {}).next;
  const u = await getUser(req.user.name);
  if (!(await checkPw(cur, u.pass_hash))) { fail(key); return res.status(400).json({ error: '目前的密碼不正確' }); }
  const bad = pwProblem(next, u.name, cur); if (bad) return res.status(400).json({ error: bad });
  const r = await pool.query('UPDATE users SET pass_hash=$2, must_change=false, sv=sv+1 WHERE name=$1 RETURNING sv', [u.name, await hashPw(next)]);
  closeSse(u.name);                                            // 其他裝置的即時連線一併斷掉；那些裝置的登入也因版本變了而失效
  res.set('Set-Cookie', cookieStr(req, { name: u.name, sv: r.rows[0].sv }));
  res.json({ ok: true });
});

app.get('/api/users/public', needReady, async (req, res) => {
  const r = await pool.query('SELECT name,display,role,disabled FROM users ORDER BY (role<>\'admin\'), created_at');
  res.json(r.rows);
});

/* ---- 帳號管理（只有管理者）---- */
const lastAdminLeft = async (excludeName) => (await pool.query("SELECT count(*)::int n FROM users WHERE role='admin' AND NOT disabled AND name<>$1", [excludeName])).rows[0].n === 0;
app.get('/api/admin/users', needReady, needAdmin, async (req, res) => {
  const r = await pool.query('SELECT name,display,role,must_change,disabled,created_at,last_login FROM users ORDER BY (role<>\'admin\'), created_at');
  res.json(r.rows);
});
app.post('/api/admin/users', needReady, needAdmin, needJson, async (req, res) => {
  const b = req.body || {}, name = String(b.name || '').trim().toLowerCase(), display = String(b.display || '').trim().slice(0, 40) || name;
  const role = b.role === 'admin' ? 'admin' : 'staff';
  if (!NAME_RE.test(name)) return res.status(400).json({ error: '帳號只能用英文小寫、數字、. _ -，長度 2–32' });
  const bad = pwProblem(b.password, name); if (bad) return res.status(400).json({ error: bad });
  if (await getUser(name)) return res.status(409).json({ error: '這個帳號已經有人用了' });
  await pool.query('INSERT INTO users(name,display,pass_hash,role,must_change) VALUES($1,$2,$3,$4,true)', [name, display, await hashPw(b.password), role]);
  res.json({ ok: true });
});
app.patch('/api/admin/users/:name', needReady, needAdmin, needJson, async (req, res) => {
  const name = req.params.name, b = req.body || {}, u = await getUser(name);
  if (!u) return res.status(404).json({ error: '找不到這個帳號' });
  const self = name === req.user.name, sets = [], vals = [name];
  const add = (col, v) => { vals.push(v); sets.push(`${col}=$${vals.length}`); };
  let bump = false;
  if (b.display !== undefined) add('display', String(b.display).trim().slice(0, 40) || name);
  if (b.role !== undefined) {
    const role = b.role === 'admin' ? 'admin' : 'staff';
    if (role !== u.role) {
      if (self) return res.status(400).json({ error: '不能改自己的角色' });
      if (u.role === 'admin' && await lastAdminLeft(name)) return res.status(400).json({ error: '至少要留一位啟用中的管理者' });
      add('role', role);
    }
  }
  if (b.disabled !== undefined && !!b.disabled !== u.disabled) {
    if (b.disabled) {
      if (self) return res.status(400).json({ error: '不能停用自己' });
      if (u.role === 'admin' && await lastAdminLeft(name)) return res.status(400).json({ error: '至少要留一位啟用中的管理者' });
      bump = true;
    }
    add('disabled', !!b.disabled);
  }
  if (b.newPassword !== undefined) {
    const bad = pwProblem(b.newPassword, name); if (bad) return res.status(400).json({ error: bad });
    add('pass_hash', await hashPw(b.newPassword)); sets.push('must_change=true'); bump = true;   // 重設後對方下次登入必須自己再改
  }
  if (bump) sets.push('sv=sv+1');
  if (!sets.length) return res.json({ ok: true });
  await pool.query(`UPDATE users SET ${sets.join(',')} WHERE name=$1`, vals);
  if (bump) closeSse(name);
  res.json({ ok: true });
});
app.delete('/api/admin/users/:name', needReady, needAdmin, async (req, res) => {
  const name = req.params.name, u = await getUser(name);
  if (!u) return res.status(404).json({ error: '找不到這個帳號' });
  if (name === req.user.name) return res.status(400).json({ error: '不能刪除自己' });
  if (u.role === 'admin' && await lastAdminLeft(name)) return res.status(400).json({ error: '至少要留一位啟用中的管理者' });
  await pool.query('DELETE FROM users WHERE name=$1', [name]);
  closeSse(name);
  res.json({ ok: true });
});

/* ---- 資料 ---- */
const sse = new Set();
function closeSse(name) { for (const c of [...sse]) if (c.name === name) { sse.delete(c); c.res.end(); } }
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

app.get('/api/stream', needReady, (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.flushHeaders(); res.write('retry: 3000\n\n');
  const c = { res, role: req.user.role, name: req.user.name }; sse.add(c);
  const hb = setInterval(() => res.write(': hb\n\n'), 25000);
  req.on('close', () => { clearInterval(hb); sse.delete(c); });
});

app.get('/api/c/:coll', needReady, guard('read'), async (req, res) => {
  const r = await pool.query('SELECT id, data FROM docs WHERE coll=$1', [req.params.coll]);
  res.json(r.rows);
});
app.post('/api/c/:coll', needReady, needJson, guard('write'), async (req, res) => {
  const id = newId();
  await pool.query('INSERT INTO docs(coll,id,data) VALUES($1,$2,$3)', [req.params.coll, id, req.body || {}]);
  broadcast(req.params.coll); res.json({ id });
});
app.put('/api/c/:coll/:id', needReady, needJson, guard('write'), async (req, res) => {
  await pool.query(`INSERT INTO docs(coll,id,data) VALUES($1,$2,$3)
    ON CONFLICT (coll,id) DO UPDATE SET data=EXCLUDED.data, version=docs.version+1, updated_at=now()`, [req.params.coll, req.params.id, req.body || {}]);
  broadcast(req.params.coll); res.json({ ok: true });
});
app.patch('/api/c/:coll/:id', needReady, needJson, guard('write'), async (req, res) => {
  const body = req.body || {}, del = Object.keys(body).filter(k => body[k] && body[k].__delete__ === true);
  const set = Object.fromEntries(Object.entries(body).filter(([k]) => !del.includes(k)));
  await pool.query(`INSERT INTO docs(coll,id,data) VALUES($1,$2,$3::jsonb)
    ON CONFLICT (coll,id) DO UPDATE SET data=(docs.data || $3::jsonb) - $4::text[], version=docs.version+1, updated_at=now()`,
    [req.params.coll, req.params.id, set, del]);
  broadcast(req.params.coll); res.json({ ok: true });
});
app.delete('/api/c/:coll/:id', needReady, guard('write'), async (req, res) => {
  await pool.query('DELETE FROM docs WHERE coll=$1 AND id=$2', [req.params.coll, req.params.id]);
  broadcast(req.params.coll); res.json({ ok: true });
});

// 管理者備份：下載全部資料（JSON）
app.get('/api/export', needReady, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  const r = await pool.query('SELECT coll,id,data FROM docs ORDER BY coll,id');
  const out = {}; r.rows.forEach(x => { (out[x.coll] ||= {})[x.id] = x.data; });
  res.set('Content-Disposition', `attachment; filename="xinhow-backup-${new Date().toISOString().slice(0, 10)}.json"`);
  res.json(out);
});


// 管理者匯入／還原：把備份或初始資料（{集合:{文件ID:資料}}）寫入資料庫，同 ID 會覆蓋
app.post('/api/import', needReady, needJson, async (req, res) => {
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
const page = f => (req, res) => res.sendFile(path.join(pub, f));
app.get('/login', (req, res) => !req.user ? page('login.html')(req, res) : res.redirect(req.user.mustChange ? '/change-password' : '/'));
app.get('/change-password', (req, res) => req.user ? page('change-password.html')(req, res) : res.redirect('/login'));
app.get('/import', (req, res) => !req.user ? res.redirect('/login') : req.user.mustChange ? res.redirect('/change-password') : req.user.role !== 'admin' ? res.status(403).send('只有管理者可以匯入') : page('import.html')(req, res));
app.get('/admin', (req, res) => !req.user ? res.redirect('/login') : req.user.mustChange ? res.redirect('/change-password') : req.user.role !== 'admin' ? res.status(403).send('只有管理者可以管理帳號') : page('admin.html')(req, res));
app.get('/shim.js', page('shim.js'));
app.get('/', (req, res) => !req.user ? res.redirect('/login') : req.user.mustChange ? res.redirect('/change-password') : page('index.html')(req, res));
app.use((req, res) => res.status(404).send('Not found'));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'server error' }); });

async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS docs(
    coll text NOT NULL, id text NOT NULL, data jsonb NOT NULL DEFAULT '{}'::jsonb,
    version int NOT NULL DEFAULT 1, updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(coll,id))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS users(
    name text PRIMARY KEY, display text NOT NULL, pass_hash text NOT NULL, role text NOT NULL CHECK (role IN ('admin','staff')),
    must_change boolean NOT NULL DEFAULT true, disabled boolean NOT NULL DEFAULT false, sv int NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(), last_login timestamptz)`);
  // 第一次啟動（沒有任何帳號）：用環境變數建立管理者／員工，初始密碼一律要求第一次登入就改掉。之後環境變數裡的密碼就不再被使用。
  const n = (await pool.query('SELECT count(*)::int n FROM users')).rows[0].n;
  if (n === 0) {
    if (!process.env.ADMIN_PASSWORD) { console.error('第一次啟動需要 ADMIN_PASSWORD 來建立管理者帳號'); process.exit(1); }
    const seed = [[(process.env.ADMIN_NAME || 'jimmy').toLowerCase(), process.env.ADMIN_DISPLAY || '楊濬騰', process.env.ADMIN_PASSWORD, 'admin']];
    if (process.env.STAFF_PASSWORD) { const sn = (process.env.STAFF_NAME || 'mio').toLowerCase(); seed.push([sn, process.env.STAFF_DISPLAY || sn.charAt(0).toUpperCase() + sn.slice(1), process.env.STAFF_PASSWORD, 'staff']); }
    for (const [name, display, pw, role] of seed) {
      if (!NAME_RE.test(name)) { console.error('帳號名稱不合法：' + name); process.exit(1); }
      await pool.query('INSERT INTO users(name,display,pass_hash,role,must_change) VALUES($1,$2,$3,$4,true)', [name, display, await hashPw(pw), role]);
    }
    console.log('已建立初始帳號：' + seed.map(x => x[0]).join(', ') + '（第一次登入需改密碼）');
  }
  // 緊急救援：忘記管理者密碼時，在 Railway 設 ADMIN_RESET=1 與 ADMIN_PASSWORD 後重啟，登入後立刻改密碼，並把 ADMIN_RESET 刪掉
  if (process.env.ADMIN_RESET === '1' && process.env.ADMIN_PASSWORD) {
    const an = (process.env.ADMIN_NAME || 'jimmy').toLowerCase();
    const r = await pool.query("UPDATE users SET pass_hash=$2, must_change=true, disabled=false, role='admin', sv=sv+1 WHERE name=$1", [an, await hashPw(process.env.ADMIN_PASSWORD)]);
    console.log(r.rowCount ? 'ADMIN_RESET：已重設 ' + an + ' 的密碼（登入後必須改密碼，請刪除 ADMIN_RESET 變數）' : 'ADMIN_RESET：找不到帳號 ' + an);
  }
  app.listen(PORT, () => console.log('listening on ' + PORT));
}
init().catch(e => { console.error(e); process.exit(1); });
