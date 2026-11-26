// Key server: key 6 giờ / 1 ngày / 3 ngày / 7 ngày / 30 ngày, lưu online trên Firebase Realtime Database.
// - Thời hạn key bắt đầu tính từ lần đầu kích hoạt.
// - Mỗi key có số thiết bị tối đa (mặc định 1). Muốn sang thiết bị mới phải reset key.
// - Đóng băng tất cả key / từng key (thời gian ngừng đếm), bù thêm giờ cho tất cả / từng key.
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
// Danh sách thiết bị của key (tương thích key cũ chỉ có deviceId)
function devicesOf(k) {
  if (Array.isArray(k.devices)) return k.devices.filter(Boolean);
  if (k.devices && typeof k.devices === 'object') return Object.values(k.devices).filter(Boolean);
  return k.deviceId ? [k.deviceId] : [];
}
function maxDev(k) {
  return k.maxDevices > 0 ? k.maxDevices : 1;
}

async function getFreeze() {
  const v = (await db.ref('config/freeze').once('value')).val();
  return v && v.since ? v : null;
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
// Trang xác minh key -> mở app (V18). Không cache, không cho nhúng iframe, không gửi referrer.
app.get(['/open', '/open.html'], (req, res) => {
  res.set({
    'Cache-Control': 'no-store',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
  });
  res.sendFile(pageFile('open.html'));
});

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

function publicInfo(k, now, freeze) {
  const expired = k.expiresAt ? now > k.expiresAt : false;
  const devs = devicesOf(k);
  return {
    duration: k.duration,
    activated: !!k.activatedAt,
    expiresAt: k.expiresAt || null,
    remainingMs: k.expiresAt ? Math.max(0, k.expiresAt - now) : DURATIONS[k.duration],
    expired,
    banned: k.status === 'banned',
    frozen: !!(freeze || k.frozenAt),
    maintenance: !!freeze,
    deviceBound: devs.length > 0,
    devices: devs.length,
    maxDevices: maxDev(k),
    resetsLeft: Math.max(0, MAX_RESETS - (k.resetCount || 0)),
  };
}

// ===== API cho app/tool của bạn gọi =====
// Lõi xác minh key (dùng chung cho /api/verify cũ và /api/web/verify mới) – logic giữ nguyên như bản cũ.
async function runVerify(key, deviceId) {
  const now = Date.now();
  let result = { ok: false, code: 'NOT_FOUND', message: 'Key không tồn tại' };
  const freeze = await getFreeze();
  await db.ref('keys/' + key).transaction((cur) => {
    if (cur === null) { result = { ok: false, code: 'NOT_FOUND', message: 'Key không tồn tại' }; return null; }
    if (cur.status === 'banned') { result = { ok: false, code: 'BANNED', message: 'Key đã bị khóa' }; return; }
    if (freeze) {
      result = { ok: false, code: 'MAINTENANCE', message: 'Hệ thống đang bảo trì, thời gian key được tạm dừng. Vui lòng quay lại sau.' };
      return;
    }
    if (cur.frozenAt) {
      result = { ok: false, code: 'FROZEN', message: 'Key đang được tạm dừng (thời gian không bị tính). Liên hệ admin.' };
      return;
    }

    const activated = !!cur.activatedAt;
    if (activated && now > cur.expiresAt) {
      result = { ok: false, code: 'EXPIRED', message: 'Key đã hết hạn' };
      return;
    }
    const devs = devicesOf(cur);
    const has = devs.includes(deviceId);
    if (!has && devs.length >= maxDev(cur)) {
      result = {
        ok: false,
        code: 'DEVICE_MISMATCH',
        message: 'Key đã đủ ' + maxDev(cur) + ' thiết bị. Vào trang reset để đổi thiết bị.',
      };
      return;
    }

    if (!activated) {
      // Lần đầu kích hoạt: bắt đầu tính giờ (cộng thêm phần bù nếu có)
      cur.activatedAt = now;
      cur.expiresAt = now + DURATIONS[cur.duration] + (cur.bonusMs || 0);
      cur.bonusMs = null;
    }
    if (!has) devs.push(deviceId);
    cur.devices = devs;
    cur.deviceId = null;
    cur.lastUsedAt = now;
    result = {
      ok: true,
      code: 'OK',
      message: activated ? 'Key hợp lệ' : 'Kích hoạt thành công',
      info: publicInfo(cur, now, null),
    };
    return cur;
  });
  return result;
}

// POST /api/verify {key, deviceId}   (API cũ – giữ nguyên để bản app cũ vẫn chạy)
app.post('/api/verify', rateLimit(60, 60 * 1000), async (req, res) => {
  const key = normKey(req.body.key);
  const deviceId = req.body.deviceId;
  if (!validKeyFormat(key) || !validDevice(deviceId)) {
    return res.json({ ok: false, code: 'BAD_REQUEST', message: 'Key hoặc deviceId không hợp lệ' });
  }
  try {
    res.json(await runVerify(key, deviceId));
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
    res.json({ ok: true, info: publicInfo(snap.val(), Date.now(), await getFreeze()) });
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
      if (devicesOf(cur).length === 0) { result = { ok: false, message: 'Key chưa gắn thiết bị nào, không cần reset' }; return; }
      if ((cur.resetCount || 0) >= MAX_RESETS) {
        result = { ok: false, message: 'Key đã hết lượt reset (' + MAX_RESETS + ' lần). Liên hệ admin.' };
        return;
      }
      cur.devices = null;
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
  const maxDevices = Math.min(Math.max(parseInt(req.body.maxDevices || '1', 10) || 1, 1), 100);
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
        maxDevices,
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
    const freeze = await getFreeze();
    const now = Date.now();
    const list = [];
    snap.forEach((c) => {
      const v = c.val();
      const devs = devicesOf(v);
      list.push({
        key: c.key,
        duration: v.duration,
        note: v.note || '',
        status: v.status,
        createdAt: v.createdAt,
        activatedAt: v.activatedAt || null,
        expiresAt: v.expiresAt || null,
        expired: v.expiresAt ? now > v.expiresAt : false,
        frozen: !!v.frozenAt,
        devices: devs.length,
        maxDevices: maxDev(v),
        bonusMs: v.bonusMs || 0,
        resetCount: v.resetCount || 0,
        lastUsedAt: v.lastUsedAt || null,
      });
    });
    list.sort((a, b) => b.createdAt - a.createdAt);
    res.json({ ok: true, keys: list, maxResets: MAX_RESETS, freeze, now });
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
      const out = await fn(ref, req.body);
      res.json(Object.assign({ ok: true }, out || {}));
    } catch (e) {
      console.error(e);
      res.status(500).json({ ok: false, message: 'Lỗi server' });
    }
  });
}
// Admin reset thiết bị: không giới hạn lượt, không tính vào resetCount
adminKeyAction('reset', (ref) => ref.update({ devices: null, deviceId: null }));
adminKeyAction('ban', (ref) => ref.update({ status: 'banned' }));
adminKeyAction('unban', (ref) => ref.update({ status: 'active' }));
adminKeyAction('delete', (ref) => ref.remove());

// Đặt số thiết bị tối đa cho 1 key
adminKeyAction('setdevices', async (ref, body) => {
  const n = parseInt(body.maxDevices, 10);
  if (!(n >= 1 && n <= 100)) return { ok: false, message: 'Số thiết bị phải từ 1 đến 100' };
  await ref.update({ maxDevices: n });
});

// Đóng băng / rã đông 1 key
adminKeyAction('freeze', async (ref, body) => {
  const on = !!body.on;
  const now = Date.now();
  const freeze = await getFreeze();
  let msg = '';
  await ref.transaction((cur) => {
    if (cur === null) return null;
    if (on) {
      if (cur.frozenAt) return;
      // đang bảo trì toàn hệ thống thì tính từ lúc bắt đầu bảo trì
      cur.frozenAt = freeze ? freeze.since : now;
      return cur;
    }
    if (!cur.frozenAt) return;
    if (cur.activatedAt && cur.expiresAt && cur.expiresAt > cur.frozenAt) {
      const end = freeze ? freeze.since : now; // phần còn lại do rã đông toàn hệ thống cộng
      const add = end - Math.max(cur.frozenAt, cur.activatedAt);
      if (add > 0) cur.expiresAt += add;
    }
    cur.frozenAt = null;
    return cur;
  });
  return msg ? { message: msg } : {};
});

// Bù thêm thời gian cho 1 key: {key, hours}
adminKeyAction('extend', async (ref, body) => {
  const hours = Number(body.hours);
  if (!(hours > 0 && hours <= 24 * 365)) return { ok: false, message: 'Số giờ phải từ 0 đến 8760' };
  const ms = Math.round(hours * H);
  const now = Date.now();
  await ref.transaction((cur) => {
    if (cur === null) return null;
    if (cur.activatedAt && cur.expiresAt) cur.expiresAt = Math.max(cur.expiresAt, now) + ms;
    else cur.bonusMs = (cur.bonusMs || 0) + ms; // chưa kích hoạt: cộng khi kích hoạt
    return cur;
  });
});

// Đóng băng / rã đông TẤT CẢ key (bảo trì): {on}
app.post('/api/admin/freeze-all', adminAuth, async (req, res) => {
  const on = !!req.body.on;
  const now = Date.now();
  try {
    const freeze = await getFreeze();
    if (on) {
      if (freeze) return res.json({ ok: true, message: 'Đang đóng băng rồi' });
      await db.ref('config/freeze').set({ since: now });
      return res.json({ ok: true });
    }
    if (!freeze) return res.json({ ok: true, message: 'Chưa đóng băng' });
    const snap = await db.ref('keys').once('value');
    const updates = {};
    let n = 0;
    snap.forEach((c) => {
      const v = c.val();
      if (!v.activatedAt || !v.expiresAt) return;
      if (v.frozenAt) return; // key đóng băng riêng sẽ tự bù khi rã đông
      if (v.expiresAt <= freeze.since) return; // đã hết hạn từ trước khi bảo trì
      const add = now - Math.max(freeze.since, v.activatedAt);
      if (add > 0) { updates['keys/' + c.key + '/expiresAt'] = v.expiresAt + add; n++; }
    });
    updates['config/freeze'] = null;
    await db.ref().update(updates);
    res.json({ ok: true, adjusted: n, addedMs: now - freeze.since });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, message: 'Lỗi server' });
  }
});

// Bù thêm thời gian cho TẤT CẢ key đang hoạt động (chưa hết hạn): {hours}
app.post('/api/admin/extend-all', adminAuth, async (req, res) => {
  const hours = Number(req.body.hours);
  if (!(hours > 0 && hours <= 24 * 365)) return res.json({ ok: false, message: 'Số giờ phải từ 0 đến 8760' });
  const ms = Math.round(hours * H);
  const now = Date.now();
  try {
    const snap = await db.ref('keys').once('value');
    const updates = {};
    let n = 0;
    snap.forEach((c) => {
      const v = c.val();
      if (!v.activatedAt || !v.expiresAt || v.expiresAt <= now) return;
      updates['keys/' + c.key + '/expiresAt'] = v.expiresAt + ms;
      n++;
    });
    if (n) await db.ref().update(updates);
    res.json({ ok: true, adjusted: n });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, message: 'Lỗi server' });
  }
});

// ===== Vượt link lấy key miễn phí (vượt 2 link liên tiếp, key 6 giờ, 1 thiết bị) =====
// Luồng: /get (bấm Lấy key) -> link rút gọn 1 -> /claim -> link rút gọn 2 -> /claim -> server tạo key.
// Biến môi trường (tùy chọn):
//   SHORTENER_API_URL  : URL API của web rút gọn, có chỗ {url}
//   SITE_URL           : link web của bạn
//   FREE_KEY_DURATION  : 6h | 1d | 3d | 7d | 30d (mặc định 6h)
//   FREE_KEY_DEVICES   : số thiết bị của key vượt link (mặc định 1)
//   MIN_SECONDS        : số giây tối thiểu mỗi lần vượt link (mặc định 25)
//   IP_COOLDOWN_HOURS  : chờ bao nhiêu giờ mới được vượt link lấy key lại (mặc định 5, 0 = không giới hạn)
//   STRICT_IP          : 1 = bắt buộc cùng IP lúc bấm và lúc nhận key (mặc định tắt)
const SHORTENER_API_URL = process.env.SHORTENER_API_URL || 'https://link4m.co/api-shorten/v2?api=6a41f075234afd17497b7953&url={url}';
const SITE_URL = (process.env.SITE_URL || 'https://key-server-p865.onrender.com').replace(/\/+$/, '');
const FREE_KEY_DURATION = DURATIONS[process.env.FREE_KEY_DURATION] ? process.env.FREE_KEY_DURATION : '6h';
const FREE_KEY_DEVICES = Math.max(parseInt(process.env.FREE_KEY_DEVICES || '1', 10) || 1, 1);
const MIN_SECONDS = parseInt(process.env.MIN_SECONDS || '25', 10);
const IP_COOLDOWN_HOURS = parseFloat(process.env.IP_COOLDOWN_HOURS || '5');
const STRICT_IP = process.env.STRICT_IP === '1';
const SESSION_TTL = 60 * 60 * 1000;
const GATE_STEPS = 2;

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
function siteBase(req) {
  return SITE_URL || (req.protocol + '://' + req.get('host'));
}

// Gọi API web rút gọn, trả về link rút gọn (hoặc null nếu lỗi)
async function makeShortLink(dest) {
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
    return null;
  }
  return link;
}

function cidHashOf(cid) {
  cid = String(cid || '');
  return /^[a-f0-9]{32}$/.test(cid) ? sha('c' + cid) : null;
}
// Thời gian (ms) còn phải chờ trước khi được vượt link lại: tính theo cả IP lẫn trình duyệt
async function cooldownWait(ipHash, cidHash) {
  if (IP_COOLDOWN_HOURS <= 0) return 0;
  const refs = [db.ref('ipcool/' + ipHash)];
  if (cidHash) refs.push(db.ref('ipcool/' + cidHash));
  const vals = await Promise.all(refs.map((r) => r.once('value')));
  let wait = 0;
  for (const v of vals) {
    const last = v.val();
    if (last) wait = Math.max(wait, last + IP_COOLDOWN_HOURS * H - Date.now());
  }
  return wait;
}
function waitMessage(wait) {
  const mins = Math.ceil(wait / 60000);
  const h = Math.floor(mins / 60), m = mins % 60;
  return 'Bạn đã nhận key rồi. Có thể vượt link lấy key mới sau ' + (h ? h + ' giờ ' : '') + m + ' phút nữa.';
}

app.get('/api/gate/info', async (req, res) => {
  let waitMs = 0;
  try { waitMs = await cooldownWait(sha(clientIp(req)), cidHashOf(req.query.cid)); } catch (e) { console.error(e); }
  res.json({
    ok: true,
    configured: !!SHORTENER_API_URL,
    duration: FREE_KEY_DURATION,
    devices: FREE_KEY_DEVICES,
    steps: GATE_STEPS,
    cooldownHours: IP_COOLDOWN_HOURS,
    waitMs,
    waitMessage: waitMs > 0 ? waitMessage(waitMs) : '',
  });
});

app.post('/api/gate/start', rateLimit(10, 60 * 1000), async (req, res) => {
  try {
    if (!SHORTENER_API_URL) return res.json({ ok: false, message: 'Admin chưa cài link vượt (SHORTENER_API_URL).' });
    const ipHash = sha(clientIp(req));
    const cidHash = cidHashOf(req.body.cid);
    const wait = await cooldownWait(ipHash, cidHash);
    if (wait > 0) return res.json({ ok: false, message: waitMessage(wait) });
    const token = crypto.randomBytes(16).toString('hex');
    const now = Date.now();
    await db.ref('sessions/' + token).set({
      createdAt: now,
      stage: 1,
      stageAt: now,
      ipHash,
      cidHash,
      uaHash: sha(req.get('user-agent') || ''),
      used: false,
    });
    const link = await makeShortLink(siteBase(req) + '/claim?t=' + token);
    if (!link) return res.json({ ok: false, message: 'Không tạo được link vượt, báo admin.' });
    res.json({ ok: true, url: link });
  } catch (e) {
    console.error('GATE START ERROR:', e);
    res.status(500).json({ ok: false, message: 'Lỗi server' });
  }
});

app.post('/api/gate/claim', rateLimit(20, 60 * 1000), async (req, res) => {
  const t = String(req.body.t || '');
  const k = String(req.body.k || '');
  if (!/^[a-f0-9]{32}$/.test(t) || (k && !/^[a-f0-9]{32}$/.test(k))) {
    return res.json({ ok: false, message: 'Link không hợp lệ.' });
  }
  const ipHash = sha(clientIp(req));
  const uaHash = sha(req.get('user-agent') || '');
  const now = Date.now();
  const newKey = genKey();
  const newT2 = crypto.randomBytes(16).toString('hex');
  const TOO_FAST = { ok: false, code: 'TOO_FAST', message: 'Bạn vượt link quá nhanh. Hãy làm đủ các bước trên trang vượt link rồi thử lại.' };
  let result = { ok: false, message: 'Link không tồn tại hoặc đã hết hạn.' };
  let sessCid = null;
  try {
    await db.ref('sessions/' + t).transaction((cur) => {
      if (cur === null) { result = { ok: false, message: 'Link không tồn tại hoặc đã hết hạn.' }; return null; }
      if (cur.uaHash !== uaHash || (STRICT_IP && cur.ipHash !== ipHash)) {
        result = { ok: false, message: 'Hãy mở link bằng đúng trình duyệt bạn đã bấm "Lấy key".' };
        return;
      }
      if (cur.used) { result = { ok: true, key: cur.key, again: true }; return; }
      if (now - cur.createdAt > SESSION_TTL) { result = { ok: false, message: 'Link đã hết hạn, hãy lấy lại.' }; return; }
      const stage = cur.stage || 1;
      const waited = now - (cur.stageAt || cur.createdAt);

      if (stage === 1) {
        if (waited < MIN_SECONDS * 1000) { result = TOO_FAST; return; }
        cur.stage = 2;
        cur.stageAt = now;
        cur.t2 = newT2;
        cur.link2 = null;
        result = { ok: true, advanced: true, t2: newT2 };
        return cur;
      }

      // stage 2: phải có đúng mã k từ link thứ hai
      if (k !== cur.t2) {
        if (cur.link2) result = { ok: true, next: true, url: cur.link2, step: 1, total: GATE_STEPS };
        else result = { ok: false, message: 'Đang chuẩn bị link thứ hai, thử lại sau vài giây.' };
        return;
      }
      if (waited < MIN_SECONDS * 1000) { result = TOO_FAST; return; }
      cur.used = true;
      cur.key = newKey;
      cur.usedAt = now;
      sessCid = cur.cidHash || null;
      result = { ok: true, key: newKey, created: true };
      return cur;
    });

    // Vừa xong link 1: tạo link rút gọn thứ hai
    if (result.ok && result.advanced) {
      const link2 = await makeShortLink(siteBase(req) + '/claim?t=' + t + '&k=' + result.t2);
      if (!link2) {
        await db.ref('sessions/' + t).update({ stage: 1, stageAt: now, t2: null, link2: null }).catch(() => {});
        return res.json({ ok: false, message: 'Không tạo được link thứ hai, thử lại sau.' });
      }
      await db.ref('sessions/' + t).update({ link2 });
      return res.json({ ok: true, next: true, url: link2, step: 1, total: GATE_STEPS });
    }

    // Vừa xong link 2: tạo key thật
    if (result.ok && result.created) {
      try {
        await db.ref('keys/' + result.key).set({
          duration: FREE_KEY_DURATION,
          maxDevices: FREE_KEY_DEVICES,
          note: 'free-gate',
          status: 'active',
          createdAt: now,
          resetCount: 0,
        });
        if (IP_COOLDOWN_HOURS > 0) {
          await db.ref('ipcool/' + ipHash).set(now);
          if (sessCid) await db.ref('ipcool/' + sessCid).set(now);
        }
      } catch (e) {
        await db.ref('sessions/' + t).update({ used: false, key: null }).catch(() => {});
        throw e;
      }
    }
    if (result.ok && result.key) result.duration = FREE_KEY_DURATION;
    res.json(result);
  } catch (e) {
    console.error('GATE CLAIM ERROR:', e);
    res.status(500).json({ ok: false, message: 'Lỗi server' });
  }
});

// =====================================================================
// ===== XÁC THỰC WEBSITE -> APP (vé 1 lần -> phiên) – bản V18 =========
// =====================================================================
// Luồng: Website nhập key -> POST /api/web/verify -> server cấp VÉ (dùng 1 lần, sống ~90s, gắn deviceId)
//        -> website mở app qua deep link muopvip://auth?ticket=... (KHÔNG chứa key)
//        -> app POST /api/auth/exchange {ticket, deviceId} -> nhận SESSION TOKEN ngẫu nhiên có hạn
//        -> app gọi POST /api/auth/check {session, deviceId} định kỳ.
// Dữ liệu lưu trên Firebase (đường dẫn riêng, KHÔNG đụng keys/, sessions/ của hệ thống vượt link):
//   authTickets/<sha256(ticket)>  = {key, deviceId, createdAt, expiresAt, used, usedAt}
//   authSessions/<sha256(token)>  = {key, deviceId, createdAt, expiresAt, revoked, lastCheckAt}
// Biến môi trường (tùy chọn):
//   AUTH_TICKET_TTL_SEC     : hạn của vé, 30..120 giây (mặc định 90)
//   AUTH_SESSION_TTL_HOURS  : hạn tối đa của phiên (mặc định 12, luôn bị chặn bởi hạn của key)
//   WEB_ORIGIN              : nếu đặt website ở domain khác server, liệt kê origin được phép (cách nhau bằng dấu phẩy)
const TICKET_TTL_MS = Math.min(Math.max(parseInt(process.env.AUTH_TICKET_TTL_SEC || '90', 10) || 90, 30), 120) * 1000;
const SESSION_MAX_MS = Math.max(parseFloat(process.env.AUTH_SESSION_TTL_HOURS || '12') || 12, 0.25) * H;
const WEB_ORIGINS = (process.env.WEB_ORIGIN || '').split(',').map((x) => x.trim().replace(/\/+$/, '')).filter(Boolean);

function randHex(bytes) { return crypto.randomBytes(bytes).toString('hex'); }
function tokenId(t) { return crypto.createHash('sha256').update(String(t)).digest('hex'); }
const TOKEN_RE = /^[a-f0-9]{64}$/;

// Kiểm tra key chỉ-đọc (không gắn thiết bị, không kích hoạt) – cùng thứ tự kiểm tra với runVerify
function evalKeyAccess(k, deviceId, now, freeze) {
  if (!k) return { ok: false, code: 'NOT_FOUND', message: 'Key không tồn tại' };
  if (k.status === 'banned') return { ok: false, code: 'BANNED', message: 'Key đã bị khóa' };
  if (freeze) return { ok: false, code: 'MAINTENANCE', message: 'Hệ thống đang bảo trì, thời gian key được tạm dừng. Vui lòng quay lại sau.' };
  if (k.frozenAt) return { ok: false, code: 'FROZEN', message: 'Key đang được tạm dừng (thời gian không bị tính). Liên hệ admin.' };
  if (k.activatedAt && now > k.expiresAt) return { ok: false, code: 'EXPIRED', message: 'Key đã hết hạn' };
  if (!devicesOf(k).includes(deviceId)) {
    return { ok: false, code: 'DEVICE_REMOVED', message: 'Thiết bị này không còn thuộc key (đã reset). Hãy xác minh lại trên website.' };
  }
  return { ok: true, code: 'OK' };
}

// Không cho trình duyệt/proxy cache các API xác thực
app.use(['/api/web', '/api/auth'], (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});
// CORS chỉ cho /api/web/* và chỉ khi admin cấu hình WEB_ORIGIN (website cùng domain với server thì không cần)
app.use('/api/web', (req, res, next) => {
  const origin = (req.get('origin') || '').replace(/\/+$/, '');
  if (origin && WEB_ORIGINS.includes(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Vary', 'Origin');
    res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// A. POST /api/web/verify {key, deviceId} -> {ok, ticket, ticketTtlSec, info}
app.post('/api/web/verify', rateLimit(20, 60 * 1000), async (req, res) => {
  const key = normKey(req.body.key);
  const deviceId = req.body.deviceId;
  if (!validKeyFormat(key)) return res.json({ ok: false, code: 'BAD_KEY_FORMAT', message: 'Key sai định dạng (dạng XXXX-XXXX-XXXX-XXXX).' });
  if (!validDevice(deviceId)) return res.json({ ok: false, code: 'BAD_DEVICE', message: 'Thiếu mã thiết bị. Hãy mở trang này bằng nút trong app Mr.mướp VIP.' });
  try {
    const r = await runVerify(key, deviceId); // kiểm tra khóa/hạn/bảo trì/đóng băng/giới hạn thiết bị + kích hoạt như /api/verify
    if (!r.ok) return res.json({ ok: false, code: r.code, message: r.message });
    const ticket = randHex(32);
    const now = Date.now();
    await db.ref('authTickets/' + tokenId(ticket)).set({
      key,
      deviceId,
      createdAt: now,
      expiresAt: now + TICKET_TTL_MS,
      used: false,
    });
    res.json({ ok: true, code: 'OK', message: r.message, ticket, ticketTtlSec: Math.round(TICKET_TTL_MS / 1000), info: r.info });
  } catch (e) {
    console.error('WEB VERIFY ERROR:', e);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR', message: 'Lỗi server' });
  }
});

// B. POST /api/auth/exchange {ticket, deviceId} -> {ok, session, expiresAt, keyExpiresAt, info}
app.post('/api/auth/exchange', rateLimit(30, 60 * 1000), async (req, res) => {
  const ticket = String(req.body.ticket || '');
  const deviceId = req.body.deviceId;
  if (!TOKEN_RE.test(ticket) || !validDevice(deviceId)) {
    return res.json({ ok: false, code: 'BAD_REQUEST', message: 'Vé hoặc deviceId không hợp lệ' });
  }
  const now = Date.now();
  let result = { ok: false, code: 'TICKET_INVALID', message: 'Vé không tồn tại' };
  let keyName = null;
  try {
    // Giao dịch nguyên tử: chỉ 1 request duy nhất đổi được vé, các request sau (hoặc song song) đều bị từ chối
    await db.ref('authTickets/' + tokenId(ticket)).transaction((cur) => {
      if (cur === null) { result = { ok: false, code: 'TICKET_INVALID', message: 'Vé không tồn tại' }; return null; }
      if (cur.used) { result = { ok: false, code: 'TICKET_USED', message: 'Vé đã được sử dụng. Hãy xác minh lại trên website.' }; return; }
      if (now > cur.expiresAt) { result = { ok: false, code: 'TICKET_EXPIRED', message: 'Vé đã hết hạn. Hãy xác minh lại trên website.' }; return; }
      if (cur.deviceId !== deviceId) { result = { ok: false, code: 'TICKET_DEVICE_MISMATCH', message: 'Vé không thuộc thiết bị này.' }; return; }
      cur.used = true;
      cur.usedAt = now;
      keyName = cur.key;
      result = { ok: true };
      return cur;
    });
    if (!result.ok) return res.json(result);

    // Kiểm tra lại key ngay lúc đổi (key có thể vừa bị khóa/bảo trì sau khi cấp vé)
    const [snap, freeze] = await Promise.all([db.ref('keys/' + keyName).once('value'), getFreeze()]);
    const k = snap.exists() ? snap.val() : null;
    const acc = evalKeyAccess(k, deviceId, now, freeze);
    if (!acc.ok) return res.json({ ok: false, code: acc.code, message: acc.message });

    const session = randHex(32);
    const expiresAt = Math.min(now + SESSION_MAX_MS, k.expiresAt || Infinity);
    await db.ref('authSessions/' + tokenId(session)).set({
      key: keyName,
      deviceId,
      createdAt: now,
      expiresAt,
      revoked: false,
      lastCheckAt: now,
    });
    res.json({
      ok: true,
      code: 'OK',
      message: 'Xác thực thành công',
      session,
      expiresAt,
      keyExpiresAt: k.expiresAt || null,
      info: publicInfo(k, now, null),
    });
  } catch (e) {
    console.error('AUTH EXCHANGE ERROR:', e);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR', message: 'Lỗi server' });
  }
});

// C. POST /api/auth/check {session, deviceId} -> {ok, ...}
app.post('/api/auth/check', rateLimit(120, 60 * 1000), async (req, res) => {
  const session = String(req.body.session || '');
  const deviceId = req.body.deviceId;
  if (!TOKEN_RE.test(session) || !validDevice(deviceId)) {
    return res.json({ ok: false, code: 'SESSION_INVALID', message: 'Phiên không hợp lệ' });
  }
  const now = Date.now();
  try {
    const ref = db.ref('authSessions/' + tokenId(session));
    const snap = await ref.once('value');
    if (!snap.exists()) return res.json({ ok: false, code: 'SESSION_INVALID', message: 'Phiên không tồn tại. Hãy xác minh lại trên website.' });
    const s = snap.val();
    if (s.revoked) return res.json({ ok: false, code: 'SESSION_REVOKED', message: 'Phiên đã bị thu hồi. Hãy xác minh lại trên website.' });
    if (now > s.expiresAt) return res.json({ ok: false, code: 'SESSION_EXPIRED', message: 'Phiên đã hết hạn. Hãy xác minh lại trên website.' });
    if (s.deviceId !== deviceId) return res.json({ ok: false, code: 'DEVICE_MISMATCH', message: 'Phiên không thuộc thiết bị này.' });

    const [ksnap, freeze] = await Promise.all([db.ref('keys/' + s.key).once('value'), getFreeze()]);
    const k = ksnap.exists() ? ksnap.val() : null;
    const acc = evalKeyAccess(k, deviceId, now, freeze);
    if (!acc.ok) {
      // Key bị xóa / thiết bị bị reset -> phiên vô hiệu hẳn. Các lỗi tạm thời (bảo trì, đóng băng, khóa, hết hạn) thì phiên giữ nguyên,
      // admin mở khóa / cộng giờ là dùng lại được ngay.
      if (acc.code === 'NOT_FOUND' || acc.code === 'DEVICE_REMOVED') await ref.update({ revoked: true }).catch(() => {});
      return res.json({ ok: false, code: acc.code, message: acc.message });
    }
    if (now - (s.lastCheckAt || 0) > 60 * 1000) await ref.update({ lastCheckAt: now }).catch(() => {});
    res.json({
      ok: true,
      code: 'OK',
      message: 'Phiên hợp lệ',
      expiresAt: s.expiresAt,
      keyExpiresAt: k.expiresAt || null,
      info: publicInfo(k, now, null),
    });
  } catch (e) {
    console.error('AUTH CHECK ERROR:', e);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR', message: 'Lỗi server' });
  }
});

// D. POST /api/auth/logout {session, deviceId} -> thu hồi phiên (app gọi khi người dùng đăng xuất)
app.post('/api/auth/logout', rateLimit(30, 60 * 1000), async (req, res) => {
  const session = String(req.body.session || '');
  const deviceId = req.body.deviceId;
  if (!TOKEN_RE.test(session) || !validDevice(deviceId)) return res.json({ ok: true });
  try {
    const ref = db.ref('authSessions/' + tokenId(session));
    const snap = await ref.once('value');
    if (snap.exists() && snap.val().deviceId === deviceId) await ref.update({ revoked: true });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, code: 'SERVER_ERROR', message: 'Lỗi server' });
  }
});

// Dọn vé / phiên đã hết hạn trên Firebase (10 phút/lần, mỗi lần tối đa 500 mục mỗi loại)
async function purgeAuth() {
  const now = Date.now();
  for (const [node, grace] of [['authTickets', 10 * 60 * 1000], ['authSessions', 24 * H]]) {
    try {
      const snap = await db.ref(node).orderByChild('expiresAt').endAt(now - grace).limitToFirst(500).once('value');
      const upd = {};
      snap.forEach((c) => { upd[node + '/' + c.key] = null; });
      if (Object.keys(upd).length) await db.ref().update(upd);
    } catch (e) {
      console.error('PURGE ' + node + ' ERROR:', e.message);
    }
  }
}
setInterval(purgeAuth, 10 * 60 * 1000).unref();

app.get('/health', (req, res) => res.send('ok'));

app.listen(PORT, () => console.log('Key server chạy ở cổng ' + PORT));
