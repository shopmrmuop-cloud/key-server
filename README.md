# Key Server

Tạo/quản lý key 6 giờ, 1 ngày, 3 ngày, 7 ngày, 30 ngày. Key lưu trên Firebase Realtime Database nên restart/redeploy server không mất.

- Thời hạn key **tính từ lần đầu kích hoạt** (lần đầu gọi `/api/verify`).
- Mỗi key gắn với 1 thiết bị. Đổi máy → vào trang chủ nhập key để **reset thiết bị** (mặc định tối đa 3 lần/key, đổi bằng `MAX_RESETS`). Admin reset không giới hạn.

## Trang web
- `/` : user nhập key để kiểm tra / reset thiết bị
- `/admin.html` : admin tạo key, xem danh sách, reset thiết bị, khóa, xóa

## 1. Tạo Firebase (miễn phí)
1. Vào https://console.firebase.google.com → dùng project có sẵn của bạn hoặc tạo mới.
2. **Build → Realtime Database → Create database** (chọn region nào cũng được, chọn *locked mode*). Copy URL dạng `https://xxxx-default-rtdb.firebaseio.com`.
3. **Project settings → Service accounts → Generate new private key** → tải file JSON về.
   Server dùng service account nên rules để khóa hết là an toàn (client không truy cập DB trực tiếp).

## 2. Deploy lên Render (miễn phí)
1. Đưa thư mục này lên GitHub (repo **private**).
2. https://render.com → New → **Web Service** → chọn repo.
   - Build command: `npm install`
   - Start command: `npm start`
3. Mục **Environment** thêm 3 biến:
   - `ADMIN_PASSWORD` = mật khẩu admin dài, khó đoán
   - `FIREBASE_DB_URL` = URL database ở bước 1
   - `FIREBASE_SERVICE_ACCOUNT` = dán **toàn bộ nội dung** file JSON (1 dòng cũng được, nhiều dòng cũng được)
   - (tùy chọn) `MAX_RESETS` = 3
4. Deploy xong có link dạng `https://ten-app.onrender.com`.

Lưu ý: gói free của Render sẽ "ngủ" sau ~15 phút không có request, request đầu tiên sau đó chậm ~30-60s. Dữ liệu key vẫn an toàn vì nằm trên Firebase. Có thể ping `/health` bằng UptimeRobot để giữ server thức. Railway, Fly.io, VPS đều chạy được tương tự.

## 3. Tích hợp vào app/tool của bạn
Gọi `POST /api/verify` với `key` và `deviceId` (ID cố định của thiết bị, ví dụ UUID sinh 1 lần rồi lưu lại).

```js
const res = await fetch('https://ten-app.onrender.com/api/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ key: 'ABCD-EFGH-JKLM-NPQR', deviceId: 'uuid-thiet-bi' }),
});
const data = await res.json();
// data.ok === true  -> cho dùng, data.info.remainingMs = thời gian còn lại
// data.ok === false -> data.code: NOT_FOUND | BANNED | EXPIRED | DEVICE_MISMATCH | BAD_REQUEST
```

Python:
```python
import requests
r = requests.post("https://ten-app.onrender.com/api/verify",
                  json={"key": "ABCD-EFGH-JKLM-NPQR", "deviceId": "uuid-thiet-bi"}).json()
```

Nên gọi verify mỗi lần mở app (và định kỳ) để key hết hạn/bị khóa là có hiệu lực ngay.

## Chạy thử trên máy
```bash
npm install
ADMIN_PASSWORD=matkhau FIREBASE_DB_URL=... FIREBASE_SERVICE_ACCOUNT="$(cat serviceAccount.json)" npm start
```
