// Key server: tạo key 6 giờ / 1 ngày / 3 ngày / 7 ngày / 30 ngày, lưu online trên Firebase Realtime Database.
// Thời hạn key bắt đầu tính từ lần đầu kích hoạt (gắn thiết bị).
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
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
// Trang web: tự tìm file trong thư mục public, nếu không có thì tìm ngay thư mục ngoài cùng
function pageFile(name) {
  const inPublic = path.join(__dirname, 'public', name);
  return fs.existsSync(inPublic) ? inPublic : path.join(__dirname, name);
}
app.get('/', (req, res) => res.sendFile(pageFile('index.html')));
app.get('/index.html', (req, res) => res.sendFile(pageFile('index.html')));
app.get(['/get', '/get.html'], (req, res) => res.sendFile(pageFile('get.html')));
app.get(['/claim', '/claim.html'], (req, res) => res.sendFile(pageFile('claim.html')));
app.get('/admin.html', (req, res) => res.sendFile(pageFile('admin.html')));

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
    console.error('CREATE KEY ERROR:', e);
    res.status(500).json({ ok: false, message: 'Lỗi server: ' + (e && e.message ? e.message : String(e)) });
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

// ===== Vượt link lấy key miễn phí =====
// Luồng: /get (bấm Lấy key) -> trang rút gọn link -> /claim?t=TOKEN -> server tự tạo key.
// Biến môi trường (tùy chọn, trừ SHORTENER_API_URL):
//   SHORTENER_API_URL  : URL API của web rút gọn, có chỗ {url}, ví dụ https://link4m.co/api-shorten/v2?api=TOKEN&url={url}
//   SITE_URL           : link web của bạn, ví dụ https://key-server-p865.onrender.com
//   FREE_KEY_DURATION  : 6h | 1d | 3d | 7d | 30d (mặc định 1d)
//   MIN_SECONDS        : số giây tối thiểu từ lúc bấm đến lúc nhận key (mặc định 25)
//   IP_COOLDOWN_HOURS  : mỗi IP nhận 1 key / bao nhiêu giờ (mặc định 24, 0 = không giới hạn)
//   STRICT_IP          : 1 = bắt buộc cùng IP lúc bấm và lúc nhận key (mặc định tắt)
const SHORTENER_API_URL = process.env.SHORTENER_API_URL || 'https://link4m.co/api-shorten/v2?api=6a41f075234afd17497b7953&url={url}';
const SITE_URL = (process.env.SITE_URL || 'https://key-server-p865.onrender.com').replace(/\/+$/, '');
const FREE_KEY_DURATION = DURATIONS[process.env.FREE_KEY_DURATION] ? process.env.FREE_KEY_DURATION : '1d';
const MIN_SECONDS = parseInt(process.env.MIN_SECONDS || '25', 10);
const IP_COOLDOWN_HOURS = parseFloat(process.env.IP_COOLDOWN_HOURS || '24');
const STRICT_IP = process.env.STRICT_IP === '1';
const SESSION_TTL = 60 * 60 * 1000;

function sha(s) {
  return crypto.createHash('sha256').update(String(s) + ADMIN_PASSWORD).digest('hex').slice(0, 32);
}
function clientIp(req) {
  const cf = req.get('cf-connecting-ip');
  if (cf) return cf.trim();
  const xff = req.get('x-forwarded-for');
  if (xff) return xff.split(',')[0].trim();
  return req.ip || '';
}

app.get('/api/gate/info', (req, res) => {
  res.json({
    ok: true,
    configured: !!SHORTENER_API_URL,
    duration: FREE_KEY_DURATION,
    cooldownHours: IP_COOLDOWN_HOURS,
  });
});

app.post('/api/gate/start', rateLimit(10, 60 * 1000), async (req, res) => {
  try {
    if (!SHORTENER_API_URL) return res.json({ ok: false, message: 'Admin chưa cài link vượt (SHORTENER_API_URL).' });
    const ipHash = sha(clientIp(req));
    if (IP_COOLDOWN_HOURS > 0) {
      const last = (await db.ref('ipcool/' + ipHash).once('value')).val();
      const wait = last ? last + IP_COOLDOWN_HOURS * H - Date.now() : 0;
      if (wait > 0) {
        const hours = Math.ceil((wait / H) * 10) / 10;
        return res.json({ ok: false, message: 'Mạng của bạn vừa nhận key rồi. Thử lại sau ' + hours + ' giờ.' });
      }
    }
    const token = crypto.randomBytes(16).toString('hex');
    await db.ref('sessions/' + token).set({
      createdAt: Date.now(),
      ipHash,
      uaHash: sha(req.get('user-agent') || ''),
      used: false,
    });
    const base = SITE_URL || (req.protocol + '://' + req.get('host'));
    const dest = base + '/claim?t=' + token;
    const apiUrl = SHORTENER_API_URL.replace('{url}', encodeURIComponent(dest));
    const r = await fetch(apiUrl);
    const text = await r.text();
    let link = null;
    try {
      const j = JSON.parse(text);
      link = j.shortenedUrl || j.shortened_url || j.short_url || j.shortUrl || j.url ||
        (j.data && (j.data.url || j.data.shortenedUrl || j.data.shortened_url)) || null;
      if (j.status && String(j.status).toLowerCase() === 'error') link = null;
    } catch (e) {
      if (/^https?:\/\//i.test(text.trim())) link = text.trim();
    }
    if (!link || !/^https?:\/\//i.test(link)) {
      console.error('SHORTENER RESPONSE:', r.status, text.slice(0, 300));
      return res.json({ ok: false, message: 'Không tạo được link vượt, báo admin.' });
    }
    res.json({ ok: true, url: link });
  } catch (e) {
    console.error('GATE START ERROR:', e);
    res.status(500).json({ ok: false, message: 'Lỗi server' });
  }
});

app.post('/api/gate/claim', rateLimit(20, 60 * 1000), async (req, res) => {
  const t = String(req.body.t || '');
  if (!/^[a-f0-9]{32}$/.test(t)) return res.json({ ok: false, message: 'Link không hợp lệ.' });
  const ipHash = sha(clientIp(req));
  const uaHash = sha(req.get('user-agent') || '');
  const now = Date.now();
  const newKey = genKey();
  let result = { ok: false, message: 'Link không tồn tại hoặc đã hết hạn.' };
  try {
    await db.ref('sessions/' + t).transaction((cur) => {
      if (cur === null) { result = { ok: false, message: 'Link không tồn tại hoặc đã hết hạn.' }; return null; }
      if (cur.uaHash !== uaHash || (STRICT_IP && cur.ipHash !== ipHash)) {
        result = { ok: false, message: 'Hãy mở link bằng đúng trình duyệt bạn đã bấm "Lấy key".' };
        return;
      }
      if (cur.used) { result = { ok: true, key: cur.key, again: true }; return; }
      if (now - cur.createdAt > SESSION_TTL) { result = { ok: false, message: 'Link đã hết hạn, hãy lấy lại.' }; return; }
      if (now - cur.createdAt < MIN_SECONDS * 1000) {
        result = { ok: false, code: 'TOO_FAST', message: 'Bạn vượt link quá nhanh. Hãy làm đủ các bước trên trang vượt link rồi thử lại.' };
        return;
      }
      cur.used = true;
      cur.key = newKey;
      cur.usedAt = now;
      result = { ok: true, key: newKey, created: true };
      return cur;
    });
    if (result.ok && result.created) {
      try {
        await db.ref('keys/' + result.key).set({
          duration: FREE_KEY_DURATION,
          note: 'free-gate',
          status: 'active',
          createdAt: now,
          resetCount: 0,
        });
        if (IP_COOLDOWN_HOURS > 0) await db.ref('ipcool/' + ipHash).set(now);
      } catch (e) {
        await db.ref('sessions/' + t).update({ used: false, key: null }).catch(() => {});
        throw e;
      }
    }
    if (result.ok) result.duration = FREE_KEY_DURATION;
    res.json(result);
  } catch (e) {
    console.error('GATE CLAIM ERROR:', e);
    res.status(500).json({ ok: false, message: 'Lỗi server' });
  }
});

app.get('/health', (req, res) => res.send('ok'));

app.listen(PORT, () => console.log('Key server chạy ở cổng ' + PORT));
