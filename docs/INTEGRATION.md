# Tích hợp dịch vụ mới với vpb-gateway

Gateway chỉ phân tuyến giao dịch ngân hàng; dịch vụ nhận phải tự kiểm tra đơn hàng, số tiền, tiền tệ và chiều giao dịch trước khi ghi có. Dùng HTTPS, giữ bí mật riêng cho mỗi tuyến. Không gửi khóa quản trị cho dịch vụ nhận.

## 1. Quản trị viên thêm tuyến

CLI (chạy trong môi trường đã cấu hình gateway):

```sh
vpb-gateway routes add --name shop --prefix SHOP --webhook https://shop.example.com/payment-hook
# Hoặc nhiều mẫu; mỗi --pattern có dạng prefix:regex
vpb-gateway routes add --name shop --webhook https://shop.example.com/payment-hook --pattern 'SHOP:[0-9]{1,12}' --pattern 'PAY:[A-Z0-9]{8}'
```

Không chạy cả hai ví dụ với cùng tên. Mặc định id_pattern là tối đa 20 chữ số. Nội dung được khớp không phân biệt hoa/thường; mã trả về chuẩn hóa hoa. Tiền tố xung đột bị từ chối, kể cả tuyến đang tắt. Regex do quản trị viên tin cậy cung cấp, tránh backtracking lớn.

Admin API tương đương:

```sh
curl -X POST "$GATEWAY/admin/routes" -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' -d '{"name":"shop","webhook_url":"https://shop.example.com/payment-hook","patterns":[{"prefix":"SHOP","id_pattern":"[0-9]{1,12}"},{"prefix":"PAY","id_pattern":"[A-Z0-9]{8}"}]}'
```

Kết quả có name, secret (HMAC webhook), api_key (chỉ đọc dữ liệu tuyến). CLI cũng in hai bí mật này khi tạo. Lưu trong kho bí mật; dùng các API rotate-secret/rotate-api-key nếu cần thay, phối hợp bên nhận vì retry dùng secret hiện tại.

## 2. Nhận webhook

POST JSON UTF-8; ví dụ minh họa:

```json
{"event_id":"evt_example","type":"transaction.matched","route":"shop","simulated":false,"transaction":{"id":42,"uid":"<sha256hex>:1","code":"SHOP123","order_id":"123","codes":["SHOP123"],"amount":10000,"currency":"VND","direction":"in","content":"SHOP123","account":"XXXX6789","bank_time":"2026-11-09T19:46:00+07:00","received_at":"2026-11-09T12:46:48Z","raw":"VPB:09/11/2026 19:46|XXXX6789|10000VND|0VND|SHOP123","assigned_manually":false}}
```

Headers: Content-Type: application/json, User-Agent: vpb-gateway/0.1.0, X-VPG-Event-Id, X-VPG-Timestamp (Unix giây), X-VPG-Signature. Chữ ký là `sha256=` + hex HMAC-SHA256(secret, timestamp + "." + **body nguyên bản**). Kiểm tra timestamp trong ±300 giây và so sánh constant-time; đồng bộ giờ máy. Không parse rồi serialize lại trước khi xác thực. Các mẫu dưới chỉ minh họa xác thực; cần thêm xử lý nghiệp vụ và giới hạn kích thước body.

PHP:

```php
<?php
$raw = file_get_contents('php://input');
$ts = $_SERVER['HTTP_X_VPG_TIMESTAMP'] ?? '';
$sig = $_SERVER['HTTP_X_VPG_SIGNATURE'] ?? '';
$expected = 'sha256=' . hash_hmac('sha256', $ts . '.' . $raw, getenv('VPG_SECRET'));
if (!ctype_digit($ts) || abs(time() - (int)$ts) > 300 || !hash_equals($expected, $sig)) {
    http_response_code(401); exit;
}
$event = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
// Trong transaction DB: INSERT event_id UNIQUE, kiểm tra đơn/số tiền rồi cập nhật.
http_response_code(204);
```

Node.js (Express, phải dùng raw trước middleware JSON):

```js
import express from 'express';
import {createHmac, timingSafeEqual} from 'node:crypto';
const app = express();
app.post('/api/vpbank', express.raw({type: 'application/json'}), async (req, res) => {
  const ts = req.get('X-VPG-Timestamp') || '';
  const sig = req.get('X-VPG-Signature') || '';
  const expected = 'sha256=' + createHmac('sha256', process.env.VPG_SECRET)
    .update(ts + '.').update(req.body).digest('hex');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (!/^\d+$/.test(ts) || Math.abs(Date.now()/1000 - Number(ts)) > 300 ||
      a.length !== b.length || !timingSafeEqual(a, b)) return res.sendStatus(401);
  const event = JSON.parse(req.body.toString('utf8'));
  // Lưu event.event_id UNIQUE và thực hiện nghiệp vụ trong transaction DB.
  res.sendStatus(204);
});
app.listen(3000);
```

Go (hàm xác thực, gọi trước khi xử lý JSON):

```go
package webhook

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "net/http"
    "strconv"
    "time"
)

func Verify(r *http.Request, raw []byte, secret string) bool {
    ts := r.Header.Get("X-VPG-Timestamp")
    stamp, err := strconv.ParseInt(ts, 10, 64)
    if err != nil || secret == "" { return false }
    now := time.Now().Unix()
    if stamp < now-300 || stamp > now+300 { return false }
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(ts + "."))
    mac.Write(raw)
    expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(expected), []byte(r.Header.Get("X-VPG-Signature")))
}
```

## 3. Ghi nhận và chống ghi có hai lần

Sau xác thực: ping không có transaction, trả 2xx; simulated=true phải bỏ qua nghiệp vụ ghi có và trả 2xx. Chỉ xử lý direction=in, currency=VND theo chính sách dịch vụ. Kiểm tra số tiền với đơn hàng phía dịch vụ; gateway không biết số tiền dự kiến.

Lưu event_id UNIQUE để chống webhook retry; dùng transaction.uid UNIQUE cho giao dịch ngân hàng để chống trùng giữa webhook và pull hoặc khi gán tay tạo sự kiện mới. Ghi dấu đã xử lý cùng cập nhật đơn/số dư trong một transaction DB. Chỉ trả 2xx sau commit bền vững, trong 10 giây; lỗi tạm thời trả non-2xx để retry. Sự kiện đã xử lý trả 2xx. Không chỉ dùng cache RAM.

Body và event_id giữ nguyên khi retry; timestamp/chữ ký được tính lại. Gửi lần đầu rồi retry sau 10s, 30s, 2m, 10m, 30m, 1h, 2h, 4h, 8h; thất bại lần cuối chuyển failed. Outbox tồn tại qua restart; có thể gửi lặp nếu tiến trình chết sau HTTP thành công nhưng trước cập nhật SQLite. Quản trị viên xem GET /admin/deliveries?status=failed và POST /admin/deliveries/{id}/redeliver; redeliver giữ event_id.

## 4. Pull API để đối soát

Dùng route API key, không dùng webhook secret:

```sh
curl -H "Authorization: Bearer $ROUTE_KEY" "$GATEWAY/v1/transactions?after_id=0&limit=100"
```

Kết quả `{ "items": [...], "next_after_id": 42 }`. Mỗi item là transaction như webhook, kèm type; bao gồm matched và unmatched được chuyển tiếp cho tuyến, không gồm simulated. Thứ tự id tăng, limit giới hạn 1..200. Trang rỗng giữ cursor đầu vào. Lặp phân trang và lưu cursor bền vững sau khi xử lý thành công toàn trang; dùng uid để không ghi có lặp với webhook. Có thể chạy định kỳ mỗi phút phía dịch vụ (gateway không tự chạy lịch đối soát này).

## 5. Giao dịch không khớp

Không khớp hoặc mơ hồ nằm trong API unmatched, dùng token unmatched riêng do quản trị viên cấp (route key không truy cập được):

```sh
curl -H "Authorization: Bearer $UNMATCHED_KEY" "$GATEWAY/v1/unmatched?status=open&after_id=0&limit=100"
curl -X POST -H "Authorization: Bearer $UNMATCHED_KEY" -H 'Content-Type: application/json' -d '{"route":"shop","order_id":"123"}' "$GATEWAY/v1/unmatched/42/assign"
curl -X POST -H "Authorization: Bearer $UNMATCHED_KEY" -H 'Content-Type: application/json' -d '{"note":"Đã kiểm tra"}' "$GATEWAY/v1/unmatched/43/ignore"
```

Danh sách là mảng; dùng id cuối cho after_id. status=all gồm cả ignored và gán tay. Assign tạo webhook matched với assigned_manually=true; gán lại cùng tuyến/order_id không tạo webhook mới, thay giao dịch đã giải quyết trả 409.

Cấu hình `[routing] forward_unmatched_to = "shop"` chỉ chuyển no_match đến tuyến đang bật dưới type=transaction.unmatched; giao dịch mơ hồ không chuyển. Dữ liệu vẫn ở unmatched API. Không tự ghi có unmatched nếu chưa xác minh nghiệp vụ.

## 6. Ping kiểm tra kết nối

```sh
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" "$GATEWAY/admin/routes/shop/test"
```

Trả event_id, xếp webhook type=ping, simulated=false, không có transaction. Receiver xác thực rồi trả 2xx, không ghi có. Xem GET /admin/deliveries?status=success để xác nhận đã gửi. CLI simulate gọi webhook thật với simulated=true; chỉ dùng để thử khi receiver đã bỏ qua simulated.

Xem thêm [hợp đồng shop](SHOP_CONTRACT.md) cho một tích hợp cụ thể, và [README](../README.md) để vận hành gateway.
