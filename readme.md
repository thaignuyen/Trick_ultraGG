1. Chạy file C:\Work\Ultra GG ( chạy bằng admin)
2. check IP wifi của máy tính -> rồi vào điện thoại cài đặt lại cấu hình wifi đang dùng (proxy) chỉnh đúng địa chỉ IP như máy tính và dặt cổng 8080
3. Cài & tin cậy chứng chỉ (lần đầu): Mở Safari vào http://mitm.it → chọn biểu tượng Apple → cài hồ sơ → vào Cài đặt → Cài đặt chung → Giới thiệu → Cài đặt tin cậy chứng nhận để bật tin cậy cho mitmproxy.
https://one.google.com/g1-sku-report -> nếu hoạt đọng thì hiện huy hiệu xanh mitmproxy cục bộ đang hoạt động · v7.6.0-mitm.
( Nếu Safari quay mãi / báo không kết nối được tới máy chủ: Khả năng cao Windows Firewall đang chặn cổng 8080 từ bên ngoài. Khi đó mở PowerShell bằng quyền Administrator trên Windows và chạy:
powershell
New-NetFirewallRule -DisplayName "Mitmproxy 8080" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow)
4. Vào google one chọn các gói( gói nào cũng được ), bấm thanh toán rồi là xong.
 ------ Nhớ vào hủy thanh toán ở phần đăng ký trong cài đặt -------