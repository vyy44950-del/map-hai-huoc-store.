# Mập Hải Hước Store — ví khách hàng và nạp tiền thủ công

## Tính năng
- Đăng ký/đăng nhập; mật khẩu băm bằng Node.js scrypt; cookie phiên HttpOnly.
- Ví theo từng tài khoản; lịch sử giao dịch.
- Khách tạo yêu cầu nạp tiền với mã chuyển khoản riêng.
- Quản trị viên kiểm tra giao dịch MB Bank rồi duyệt/từ chối thủ công.
- Chỉ khi quản trị duyệt, số dư mới được cộng; thao tác duyệt có transaction và chống duyệt lặp.
- Mua sản phẩm bằng số dư, trừ tiền và ghi sổ cái trong một transaction.

## Chạy thử
Cần Node.js 20+ và máy chủ hỗ trợ ứng dụng Node.js + SQLite có lưu trữ bền vững.

```bash
npm install
cp .env.example .env
```
Sửa `.env`: đặt `ADMIN_USERNAME` và `ADMIN_PASSWORD` mạnh, xác nhận `BANK_ACCOUNT` và `BANK_OWNER`. Không commit hoặc chia sẻ `.env`.

```bash
npm start
```
Mở `http://localhost:3000`. Trang quản trị ở `/admin.html`; trình duyệt yêu cầu Basic Auth theo biến môi trường quản trị.

## Quy trình nạp thủ công
1. Khách đăng ký/đăng nhập, vào Nạp tiền, nhập số tiền.
2. Website tạo mã chuyển khoản riêng (MHH...).
3. Khách chuyển khoản đúng số tiền và nội dung vào MB Bank, gửi biên lai cho cửa hàng.
4. Chủ tài khoản tự kiểm tra giao dịch thực tế trong ứng dụng MB Bank (không duyệt chỉ dựa vào ảnh biên lai).
5. Mở `/admin.html`, đăng nhập quản trị, duyệt yêu cầu phù hợp. Ví khách được cộng tiền.

## Cảnh báo triển khai thật
- Đây là bộ khung ứng dụng, không phải website đã được xuất bản trên Internet. Cần deploy lên máy chủ Node.js, bật HTTPS, cấu hình backup SQLite và giám sát.
- Đổi mật khẩu quản trị mặc định trước khi deploy. Không đưa thông tin quản trị vào frontend.
- Cần thêm giới hạn tốc độ, CSRF phù hợp với cấu hình domain, quy trình khôi phục mật khẩu, xác minh email/điện thoại, điều khoản, chính sách riêng tư, hỗ trợ và kiểm thử bảo mật trước khi mở công khai.
- Không có xác nhận ngân hàng tự động; admin phải kiểm tra tiền vào tài khoản thật trước khi duyệt.
- Việc nạp tiền tạo số dư có thể phát sinh nghĩa vụ pháp lý/thuế và quy định về trung gian thanh toán hoặc ví điện tử. Chỉ vận hành sau khi xác minh mô hình kinh doanh phù hợp quy định tại nơi hoạt động.
- Số dư là điểm nội bộ để mua hàng trong cửa hàng; không có rút tiền/hoàn tiền tự động.
- Giao dịch mua chỉ ghi nhận đơn, không tự động giao sản phẩm. Cần bổ sung quy trình giao hàng và xử lý hoàn/huỷ đơn.
