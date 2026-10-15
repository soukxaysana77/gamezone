const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
// 'mock' = จำลองการจ่ายเงิน (ใช้ตอนพัฒนา) — ของจริงให้เปลี่ยนเป็น gateway แล้วยืนยันผ่าน webhook
const PAYMENT_MODE = process.env.PAYMENT_MODE || 'mock';
const HEARTBEAT_MAX_CHARGE = 30; // วินาทีสูงสุดที่หักได้ต่อ heartbeat หนึ่งครั้ง
const SESSION_STALE = 60;        // ไม่มี heartbeat เกินนี้ = เลิกเล่นแล้ว
const LOGIN_TTL_DAYS = 7;

const PACKAGES = [
  { id: 'p30m', name: '30 นาที', price: 20, seconds: 30 * 60 },
  { id: 'p1h', name: '1 ชั่วโมง', price: 35, seconds: 60 * 60 },
  { id: 'p3h', name: '3 ชั่วโมง', price: 90, seconds: 3 * 60 * 60 },
  { id: 'p10h', name: '10 ชั่วโมง', price: 250, seconds: 10 * 60 * 60 },
];

const GAMES = [
  { id: 'snake', title: 'Snake', desc: 'งูกินผลไม้ คลาสสิก', color: '#22c55e', icon: '🐍' },
  { id: '2048', title: '2048', desc: 'รวมตัวเลขให้ถึง 2048', color: '#f59e0b', icon: '🔢' },
  { id: 'flappy', title: 'Flappy Dot', desc: 'กระโดดหลบท่อ', color: '#3b82f6', icon: '🐤' },
];

// ---------- Database ----------
// บน Render ให้ตั้ง DATA_DIR เป็น path ของ Persistent Disk ไม่งั้นข้อมูลหายทุกครั้งที่ deploy
const DATA_DIR = process.env.DATA_DIR || __dirname;
const db = new DatabaseSync(path.join(DATA_DIR, 'data.db'));
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    balance_seconds INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS logins (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    package_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    seconds INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL,
    paid_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS play_sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    game_id TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    last_tick INTEGER NOT NULL,
    seconds_used INTEGER NOT NULL DEFAULT 0,
    ended_at INTEGER
  );
`);

const now = () => Math.floor(Date.now() / 1000);
const newId = () => crypto.randomBytes(16).toString('hex');

function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(pw, stored) {
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(pw, salt, 64);
  return crypto.timingSafeEqual(test, Buffer.from(hash, 'hex'));
}

function getUser(id) {
  return db.prepare('SELECT id, username, balance_seconds FROM users WHERE id = ?').get(id);
}

// หักเวลาของ session ที่ยังเปิดอยู่ แล้วคืนยอดคงเหลือ
function chargeSession(s, t = now()) {
  const elapsed = Math.max(0, Math.min(t - s.last_tick, HEARTBEAT_MAX_CHARGE));
  const user = getUser(s.user_id);
  const charge = Math.min(elapsed, user.balance_seconds);
  db.prepare('UPDATE users SET balance_seconds = balance_seconds - ? WHERE id = ?').run(charge, s.user_id);
  db.prepare('UPDATE play_sessions SET last_tick = ?, seconds_used = seconds_used + ? WHERE id = ?').run(t, charge, s.id);
  return user.balance_seconds - charge;
}

function endSession(id, t = now()) {
  db.prepare('UPDATE play_sessions SET ended_at = ? WHERE id = ? AND ended_at IS NULL').run(t, id);
}

// ปิด session ที่ขาด heartbeat ไปนาน (เช่นปิดแท็บ) — ไม่หักเวลาช่วงที่หายไป
function closeStaleSessions() {
  const t = now();
  db.prepare('UPDATE play_sessions SET ended_at = last_tick WHERE ended_at IS NULL AND last_tick < ?').run(t - SESSION_STALE);
}
setInterval(closeStaleSessions, 15000);

function activeSession(userId) {
  closeStaleSessions();
  return db.prepare('SELECT * FROM play_sessions WHERE user_id = ? AND ended_at IS NULL').get(userId);
}

// ---------- App ----------
const app = express();
const IS_PROD = process.env.NODE_ENV === 'production';
app.set('trust proxy', 1); // Render อยู่หลัง proxy ที่ทำ HTTPS ให้
app.use(express.json());

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((c) => {
    const i = c.indexOf('=');
    if (i > 0) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}

app.use((req, res, next) => {
  const token = parseCookies(req).sid;
  if (token) {
    const row = db.prepare('SELECT user_id FROM logins WHERE token = ? AND expires_at > ?').get(token, now());
    if (row) req.user = getUser(row.user_id);
  }
  next();
});

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบ' });
  next();
}

function setLoginCookie(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO logins (token, user_id, expires_at) VALUES (?, ?, ?)')
    .run(token, userId, now() + LOGIN_TTL_DAYS * 86400);
  res.cookie('sid', token, { httpOnly: true, sameSite: 'lax', secure: IS_PROD, maxAge: LOGIN_TTL_DAYS * 86400 * 1000 });
}

// --- Auth ---
app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username || '')) {
    return res.status(400).json({ error: 'ชื่อผู้ใช้ต้องเป็น a-z, 0-9 หรือ _ ยาว 3-20 ตัว' });
  }
  if (typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ error: 'รหัสผ่านต้องยาวอย่างน้อย 6 ตัว' });
  }
  if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) {
    return res.status(409).json({ error: 'ชื่อผู้ใช้นี้ถูกใช้แล้ว' });
  }
  const r = db.prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)')
    .run(username, hashPassword(password), now());
  setLoginCookie(res, Number(r.lastInsertRowid));
  res.json({ ok: true });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username || '');
  if (!row || !verifyPassword(String(password || ''), row.password_hash)) {
    return res.status(401).json({ error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
  }
  setLoginCookie(res, row.id);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  const token = parseCookies(req).sid;
  if (token) db.prepare('DELETE FROM logins WHERE token = ?').run(token);
  res.clearCookie('sid');
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  res.json({ user: req.user || null });
});

// --- Catalog ---
app.get('/api/games', (req, res) => res.json(GAMES));
app.get('/api/packages', (req, res) => res.json({ packages: PACKAGES, paymentMode: PAYMENT_MODE }));

// --- Top-up ---
app.post('/api/topup', requireAuth, (req, res) => {
  const pkg = PACKAGES.find((p) => p.id === req.body?.packageId);
  if (!pkg) return res.status(400).json({ error: 'ไม่พบแพ็กเกจ' });
  const id = newId();
  db.prepare('INSERT INTO orders (id, user_id, package_id, amount, seconds, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, req.user.id, pkg.id, pkg.price, pkg.seconds, now());
  res.json({ orderId: id, amount: pkg.price });
});

// เพิ่มเวลาเมื่อชำระเงินสำเร็จ — ทำครั้งเดียวต่อ order เท่านั้น
function markOrderPaid(orderId) {
  const r = db.prepare("UPDATE orders SET status = 'paid', paid_at = ? WHERE id = ? AND status = 'pending'").run(now(), orderId);
  if (r.changes !== 1) return false;
  const o = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  db.prepare('UPDATE users SET balance_seconds = balance_seconds + ? WHERE id = ?').run(o.seconds, o.user_id);
  return true;
}

// จำลองการจ่ายเงิน — ของจริงต้องลบ route นี้ แล้วเรียก markOrderPaid จาก webhook ของ payment gateway
app.post('/api/topup/:id/mock-pay', requireAuth, (req, res) => {
  if (PAYMENT_MODE !== 'mock') return res.status(403).json({ error: 'ปิดการจ่ายเงินจำลองแล้ว' });
  const o = db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!o) return res.status(404).json({ error: 'ไม่พบรายการ' });
  if (!markOrderPaid(o.id)) return res.status(409).json({ error: 'รายการนี้ชำระแล้ว' });
  res.json({ ok: true, balance: getUser(req.user.id).balance_seconds });
});

app.post('/api/topup/:id/cancel', requireAuth, (req, res) => {
  const r = db.prepare("UPDATE orders SET status = 'cancelled' WHERE id = ? AND user_id = ? AND status = 'pending'")
    .run(req.params.id, req.user.id);
  if (r.changes !== 1) return res.status(409).json({ error: 'ยกเลิกรายการนี้ไม่ได้' });
  res.json({ ok: true });
});

app.get('/api/orders', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT id, package_id, amount, seconds, status, created_at, paid_at FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 20').all(req.user.id));
});

// --- Play time ---
app.post('/api/play/start', requireAuth, (req, res) => {
  const game = GAMES.find((g) => g.id === req.body?.gameId);
  if (!game) return res.status(400).json({ error: 'ไม่พบเกม' });
  const existing = activeSession(req.user.id);
  if (existing) {
    chargeSession(existing);
    endSession(existing.id); // เล่นได้ทีละเกม
  }
  const user = getUser(req.user.id);
  if (user.balance_seconds <= 0) return res.status(402).json({ error: 'เวลาหมดแล้ว กรุณาเติมเงิน', balance: 0 });
  const id = newId();
  const t = now();
  db.prepare('INSERT INTO play_sessions (id, user_id, game_id, started_at, last_tick) VALUES (?, ?, ?, ?, ?)')
    .run(id, req.user.id, game.id, t, t);
  res.json({ sessionId: id, balance: user.balance_seconds });
});

app.post('/api/play/heartbeat', requireAuth, (req, res) => {
  const s = activeSession(req.user.id);
  if (!s || s.id !== req.body?.sessionId) return res.status(410).json({ error: 'เซสชันการเล่นสิ้นสุดแล้ว', ended: true });
  const balance = chargeSession(s);
  if (balance <= 0) {
    endSession(s.id);
    return res.json({ balance: 0, ended: true });
  }
  res.json({ balance, ended: false });
});

app.post('/api/play/stop', requireAuth, (req, res) => {
  const s = activeSession(req.user.id);
  if (s && s.id === req.body?.sessionId) {
    chargeSession(s);
    endSession(s.id);
  }
  res.json({ balance: getUser(req.user.id).balance_seconds });
});

// ไฟล์เกมเปิดได้เฉพาะตอนที่มี session การเล่นของเกมนั้นอยู่
app.use('/games/:gameId', (req, res, next) => {
  const s = req.user && activeSession(req.user.id);
  if (!s || s.game_id !== req.params.gameId) return res.status(403).send('ต้องเริ่มเล่นจากหน้าเว็บและมีเวลาคงเหลือ');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
//app.use(express.static(__dirname));
app.listen(PORT, () => console.log(`Game portal running at http://localhost:${PORT} (payment: ${PAYMENT_MODE})`));
