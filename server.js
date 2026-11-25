// Key server: tạo key 6 giờ / 1 ngày / 3 ngày / 7 ngày / 30 ngày, lưu online trên Firebase Realtime Database.
// Thời hạn key bắt đầu tính từ lần đầu kích hoạt (gắn thiết bị).
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const admin = require('firebase-admin');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const DB_URL = process.env.FIREBASE_DB_URL;
const SA_JSON = process.env.FIREBASE_SERVICE_ACCOUNT;
const MAX_RESETS = parseInt(process.env.MAX_RESETS || '3', 10); // số lần user tự reset thiết bị / key

if (!ADMIN_PASSWORD || !DB_URL || !SA_JSON) {
  console.error('Thiếu biến môi trường: ADMIN_PASSWORD, FIREBASE_DB_URL, FIREBASE_SERVICE_ACCOUNT');
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(SA_JSON)),
  databaseURL: DB_URL,
});
const db = admin.database();

const H = 3600 * 1000;
const DURATIONS = {
  '6h': 6 * H,
  '1d': 24 * H,
  '3d': 72 * H,
  '7d': 7 * 24 * H,
  '30d': 30 * 24 * H,
};

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function genKey() {
  const bytes = crypto.randomBytes(16);
  let s = '';
  for (let i = 0; i < 16; i++) {
    s += ALPHABET[bytes[i] % ALPHABET.length];
    if (i % 4 === 3 && i < 15) s += '-';
  }
  return s;
}

function normKey(k) {
  return String(k || '').trim().toUpperCase();
}
function validKeyFormat(k) {
  return /^[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$/.test(k);
}
function validDevice(d) {
  return typeof d === 'string' && d.length >= 4 && d.length <= 200;
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Rate limit đơn giản theo IP
const hits = new Map();
function rateLimit(max, windowMs) {
  return (req, res, next) => {
    const id = req.ip + req.path;
    const now = Date.now();
    const rec = hits.get(id) || { n: 0, t: now };
    if (now - rec.t > windowMs) { rec.n = 0; rec.t = now; }
    rec.n++;
    hits.set(id, rec);
    if (rec.n > max) return res.status(429).json({ ok: false, message: 'Thao tác quá nhanh, thử lại sau.' });
    next();
  };
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of hits) if (now - v.t > 10 * 60 * 1000) hits.delete(k);
}, 5 * 60 * 1000).unref();

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
function adminAuth(req, res, next) {
  if (!safeEqual(req.get('x-admin-token') || '', ADMIN_PASSWORD)) {
    return res.status(401).json({ ok: false, message: 'Sai mật khẩu admin' });
  }
  next();
}

function publicInfo(k, now) {
  const expired = k.expiresAt ? now > k.expiresAt : false;
  return {
    duration: k.duration,
    activated: !!k.activatedAt,
    expiresAt: k.expiresAt || null,
    remainingMs: k.expiresAt ? Math.max(0, k.expiresAt - now) : DURATIONS[k.duration],
    expired,
    banned: k.status === 'banned',
    deviceBound: !!k.deviceId,
    resetsLeft: Math.max(0, MAX_RESETS - (k.resetCount || 0)),
  };
}

// ===== API cho app/tool của bạn gọi =====
// POST /api/verify {key, deviceId}
app.post('/api/verify', rateLimit(60, 60 * 1000), async (req, res) => {
  const key = normKey(req.body.key);
  const deviceId = req.body.deviceId;
  if (!validKeyFormat(key) || !validDevice(deviceId)) {
    return res.json({ ok: false, code: 'BAD_REQUEST', message: 'Key hoặc deviceId không hợp lệ' });
  }
  const now = Date.now();
  let result = { ok: false, code: 'NOT_FOUND', message: 'Key không tồn tại' };
  try {
    await db.ref('keys/' + key).transaction((cur) => {
      if (cur === null) { result = { ok: false, code: 'NOT_FOUND', message: 'Key không tồn tại' }; return null; }
      if (cur.status === 'banned') { result = { ok: false, code: 'BANNED', message: 'Key đã bị khóa' }; return; }

      if (!cur.deviceId) {
        if (!cur.activatedAt) {
          // Lần đầu kích hoạt: bắt đầu tính giờ
          cur.activatedAt = now;
          cur.expiresAt = now + DURATIONS[cur.duration];
        } else if (now > cur.expiresAt) {
          result = { ok: false, code: 'EXPIRED', message: 'Key đã hết hạn' };
          return;
        }
        cur.deviceId = deviceId;
        cur.lastUsedAt = now;
        result = { ok: true, code: 'OK', message: 'Kích hoạt thành công', info: publicInfo(cur, now) };
        return cur;
      }

      if (cur.deviceId !== deviceId) {
        result = { ok: false, code: 'DEVICE_MISMATCH', message: 'Key đang dùng trên thiết bị khác. Vào trang reset để đổi thiết bị.' };
        return;
      }
      if (now > cur.expiresAt) {
        result = { ok: false, code: 'EXPIRED', message: 'Key đã hết hạn' };
        return;
      }
      cur.lastUsedAt = now;
      result = { ok: true, code: 'OK', message: 'Key hợp lệ', info: publicInfo(cur, now) };
      return cur;
    });
    res.json(result);
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR', message: 'Lỗi server' });
  }
});

// POST /api/status {key}  -> xem thông tin key (không gắn thiết bị)
app.post('/api/status', rateLimit(30, 60 * 1000), async (req, res) => {
  const key = normKey(req.body.key);
  if (!validKeyFormat(key)) return res.json({ ok: false, message: 'Key sai định dạng' });
  try {
    const snap = await db.ref('keys/' + key).once('value');
    if (!snap.exists()) return res.json({ ok: false, message: 'Key không tồn tại' });
    res.json({ ok: true, info: publicInfo(snap.val(), Date.now()) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, message: 'Lỗi server' });
  }
});

// POST /api/reset {key}  -> user tự reset thiết bị (giới hạn MAX_RESETS lần/key)
app.post('/api/reset', rateLimit(10, 60 * 1000), async (req, res) => {
  const key = normKey(req.body.key);
  if (!validKeyFormat(key)) return res.json({ ok: false, message: 'Key sai định dạng' });
  const now = Date.now();
  let result = { ok: false, message: 'Key không tồn tại' };
  try {
    await db.ref('keys/' + key).transaction((cur) => {
      if (cur === null) { result = { ok: false, message: 'Key không tồn tại' }; return null; }
      if (cur.status === 'banned') { result = { ok: false, message: 'Key đã bị khóa' }; return; }
      if (cur.expiresAt && now > cur.expiresAt) { result = { ok: false, message: 'Key đã hết hạn, không thể reset' }; return; }
      if (!cur.deviceId) { result = { ok: false, message: 'Key chưa gắn thiết bị nào, không cần reset' }; return; }
      if ((cur.resetCount || 0) >= MAX_RESETS) {
        result = { ok: false, message: 'Key đã hết lượt reset (' + MAX_RESETS + ' lần). Liên hệ admin.' };
        return;
      }
      cur.deviceId = null;
      cur.resetCount = (cur.resetCount || 0) + 1;
      cur.lastResetAt = now;
      result = {
        ok: true,
        message: 'Đã reset thiết bị. Mở app và nhập key để dùng trên thiết bị mới.',
        resetsLeft: MAX_RESETS - cur.resetCount,
      };
      return cur;
    });
    res.json(result);
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, message: 'Lỗi server' });
  }
});

// ===== API admin =====
app.post('/api/admin/create', adminAuth, async (req, res) => {
  const duration = req.body.duration;
  const count = Math.min(Math.max(parseInt(req.body.count || '1', 10), 1), 100);
  const note = String(req.body.note || '').slice(0, 100);
  if (!DURATIONS[duration]) return res.json({ ok: false, message: 'Loại key không hợp lệ' });
  try {
    const created = [];
    const updates = {};
    while (created.length < count) {
      const k = genKey();
      if (updates['keys/' + k]) continue;
      updates['keys/' + k] = {
        duration,
        note,
        status: 'active',
        createdAt: Date.now(),
        resetCount: 0,
      };
      created.push(k);
    }
    await db.ref().update(updates);
    res.json({ ok: true, keys: created });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, message: 'Lỗi server' });
  }
});

app.get('/api/admin/keys', adminAuth, async (req, res) => {
  try {
    const snap = await db.ref('keys').once('value');
    const now = Date.now();
    const list = [];
    snap.forEach((c) => {
      const v = c.val();
      list.push({
        key: c.key,
        duration: v.duration,
        note: v.note || '',
        status: v.status,
        createdAt: v.createdAt,
        activatedAt: v.activatedAt || null,
        expiresAt: v.expiresAt || null,
        expired: v.expiresAt ? now > v.expiresAt : false,
        deviceId: v.deviceId || null,
        resetCount: v.resetCount || 0,
        lastUsedAt: v.lastUsedAt || null,
      });
    });
    list.sort((a, b) => b.createdAt - a.createdAt);
    res.json({ ok: true, keys: list, maxResets: MAX_RESETS });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, message: 'Lỗi server' });
  }
});

function adminKeyAction(name, fn) {
  app.post('/api/admin/' + name, adminAuth, async (req, res) => {
    const key = normKey(req.body.key);
    if (!validKeyFormat(key)) return res.json({ ok: false, message: 'Key sai định dạng' });
    try {
      const ref = db.ref('keys/' + key);
      const snap = await ref.once('value');
      if (!snap.exists()) return res.json({ ok: false, message: 'Key không tồn tại' });
      await fn(ref);
      res.json({ ok: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ ok: false, message: 'Lỗi server' });
    }
  });
}
// Admin reset thiết bị: không giới hạn lượt, không tính vào resetCount
adminKeyAction('reset', (ref) => ref.update({ deviceId: null }));
adminKeyAction('ban', (ref) => ref.update({ status: 'banned' }));
adminKeyAction('unban', (ref) => ref.update({ status: 'active' }));
adminKeyAction('delete', (ref) => ref.remove());

app.get('/health', (req, res) => res.send('ok'));

app.listen(PORT, () => console.log('Key server chạy ở cổng ' + PORT));
