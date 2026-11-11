# VPBank notification gateway

Dự án cá nhân chuyển thông báo giao dịch từ ứng dụng VPBank thành webhook có chữ ký HMAC. Dịch vụ lưu SQLite, phân tuyến theo mã chuyển khoản, chống trùng giao dịch và gửi lại webhook khi bên nhận lỗi.

**Tuyên bố miễn trừ:** Đây là dự án cá nhân, không liên kết với, được tài trợ hay được VPBank chứng thực. Dự án dựa trên push notification của ứng dụng VPBank và các giao diện không chính thức; có thể ngừng hoạt động hoặc vi phạm điều khoản của ngân hàng. Bạn tự chịu rủi ro khi sử dụng. Không có bảo hành. Không dùng webhook làm bằng chứng duy nhất mà không đối chiếu đơn hàng, số tiền và tài khoản nhận.

**English summary:** A personal, unofficial VPBank app push-notification gateway with signed webhooks. Not affiliated with or endorsed by VPBank. Unofficial interfaces may break or violate bank terms. Use at your own risk, without warranty.

## Cài đặt

Cần Python 3.11+, Linux/systemd khi chạy dịch vụ. Sao chép mã nguồn vào máy của bạn rồi:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install --require-hashes -r requirements-build.lock
pip install --no-build-isolation --require-hashes -r requirements.lock
pip install --no-deps --no-build-isolation .
cp deploy/config.example.toml config.toml
vpb-gateway --config config.toml doctor
```

Installer tùy chọn cho Debian/Ubuntu: `sudo sh install.sh`. Installer dùng `/opt/vpb-gateway`, `/etc/vpb-gateway`, `/var/lib/vpb-gateway` và tạo user riêng `vpbgw`. Đọc script trước khi chạy; dịch vụ chính chưa được bật tự động. Cài OpenSSL nếu dùng backup mã hóa, cấp certificate riêng tại `/etc/vpb-gateway/backup-cert.pem`; giữ khóa giải mã ngoại tuyến. Backup mặc định chỉ lưu cục bộ, người vận hành tự chọn nơi sao lưu ngoài máy.

Chỉnh config (đặc biệt token/Telegram nếu dùng), giữ file state và DB bí mật. Firebase app configuration không được đóng gói: người vận hành tự cung cấp `VPG_FIREBASE_PROJECT_ID`, `VPG_FIREBASE_APP_ID`, `VPG_FIREBASE_API_KEY`, `VPG_FIREBASE_SENDER_ID` phù hợp với ứng dụng. Nạp các biến này từ môi trường được bảo vệ (systemd EnvironmentFile do bạn tạo, quyền 0600); không đưa giá trị thật vào Git. Thiếu biến sẽ làm đăng ký/listener không hoạt động. Đăng ký ngân hàng bằng CLI tương tác `vpb-gateway --config config.toml register --key YOUR_REGISTRATION_KEY`; không đặt PIN trên dòng lệnh. Không chia sẻ file state. Khởi động bằng `vpb-gateway --config config.toml run`, hoặc bật unit systemd sau khi cấu hình. TLS reverse proxy mẫu ở `deploy/Caddyfile.example`; hạn chế truy cập API quản trị.

Bản public không gồm trang web admin. `/admin/ui` và `/admin/` trả 404 khi thiếu HTML; admin API vẫn có và cần token. Tạo token với `vpb-gateway tokens admin` hoặc `tokens unmatched`, lưu kết quả trong kho bí mật. Không đưa token vào lịch sử shell/log công khai.

## Webhook và vận hành

Xem [docs/INTEGRATION.md](docs/INTEGRATION.md). Route có khóa riêng; HMAC ký body nguyên bản kèm timestamp. Bên nhận kiểm chữ ký, độ lệch thời gian tối đa 300 giây, giao dịch thật, chiều tiền vào, tiền tệ, tài khoản, số tiền và mã đơn; ghi nhận idempotent trước khi trả 2xx. Ping/simulation không được ghi có.

`GET /healthz` dùng cho giám sát; `doctor` thực hiện kiểm tra kết nối. Units prune/backup nằm trong `deploy/`. Không mở admin API ra Internet mà không có TLS và kiểm soát truy cập. Lưu state/DB/backup với quyền hạn chế.

## Kiểm thử

```sh
pip install -e '.[test]'
python -m pytest -q
```

Test dùng dữ liệu giả và HTTP mock, không cần tài khoản ngân hàng thật. Demo cục bộ: `python -m tests.demo`.

## Giấy phép và bảo mật

SPDX: `GPL-3.0-only`. Toàn văn tại [LICENSE](LICENSE). Báo cáo lỗ hổng qua GitHub private vulnerability reporting theo [SECURITY.md](SECURITY.md).
