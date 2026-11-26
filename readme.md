1. Chạy file `C:\Work\Ultra GG\chay_g1_acq.bat` (nhấp phải -> Run as administrator để mở port / cài đặt nếu cần).
2. Kiểm tra IP Wi-Fi (IPv4) của máy tính được in ra trên màn hình -> vào iPhone **Cài đặt → Wi-Fi → (i) → Định cấu hình Proxy → Thủ công**, nhập đúng IP máy tính và cổng `8080`.
3. Cài & tin cậy chứng chỉ mitmproxy (chỉ làm lần đầu):
   - Mở Safari truy cập `http://mitm.it` → chọn biểu tượng Apple → tải và cài đặt hồ sơ.
   - Vào **Cài đặt → Cài đặt chung → VPN & Quản lý thiết bị** để cài đặt hồ sơ `mitmproxy`.
   - Vào **Cài đặt → Cài đặt chung → Giới thiệu → Cài đặt tin cậy chứng nhận** để bật tin cậy hoàn toàn cho `mitmproxy`.
4. Kiểm tra trang quản lý & báo cáo cục bộ:
   - Mở Safari vào `https://one.google.com/g1-sku-report` → nếu hoạt động đúng sẽ hiện huy hiệu xanh `mitmproxy cục bộ đang hoạt động · v7.12.0-mitm`.
   - Nếu Safari quay mãi / không kết nối được, khả năng cao Windows Firewall đang chặn cổng `8080`. Mở PowerShell với quyền Administrator và chạy:
     ```powershell
     New-NetFirewallRule -DisplayName "Mitmproxy 8080" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow
     ```
5. Chọn gói / mẫu ánh xạ (tích hợp từ `crhywun/g1-acq` v7.12.0):
   - Mặc định (`discount75`):
     - `g1.ios.2tb.` (prefix) → `g1.2tb.ai.12months_ip_90p`
     - `g1.ios.20tb.m.v2` (exact) → `g1.20tb.3months_ip_75p.acq`
     - `g1.ios.30tb.ai.pro.m` (exact) → `g1.ai.ultra.3months_ip_75p.acq`
   - Trong trang `https://one.google.com/g1-sku-report`, có sẵn **5 mẫu ánh xạ nhanh (1 lần nhấn)**:
     - **1 CNY mở Pro** (`pro-1yuan`): `g1.ios.2tb.` → `com.google.gemini.2tb.ai.m.3month_ip_99p` (tự động tắt quy tắc cũ `g1.ios.20tb.m.v2 → Gemini` nếu đang bật)
     - **Thổ Nhĩ Kỳ 20TB** (`tr-ultra-20tb`): `g1.ios.20tb.m.v2` → `g1.ios.20tb.m`
     - **Thổ Nhĩ Kỳ 30TB** (`tr-ultra-30tb`): `g1.ios.30tb.ai.pro.m` → `g1.ios.30tb.m`
     - **Ultra 20TB / 30TB 75p** (`ultra-75p`): chuyển 20TB / 30TB sang `75p`
     - **2TB / Pro 12 tháng 90p** (`pro-12months-90p`): `g1.ios.2tb.` → `g1.2tb.ai.12months_ip_90p`
   - Hỗ trợ **quản lý ánh xạ thủ công** (thêm/sửa/bật-tắt/xóa/khôi phục mặc định, tối đa 30 quy tắc) cho cả 3 namespace `g1.*`, `com.google.one.*`, `com.google.gemini.*`, có nút **Dùng làm SKU nguồn** ngay trên bảng SKU đã thu thập (ví dụ nếu trang hiển thị `g1.ios.ai.2tb.*`).
6. Sau khi lưu mẫu hoặc quy tắc trên `https://one.google.com/g1-sku-report`, **đóng hẳn và mở lại Google App / trang chọn gói Google One**, chọn gói cần đăng ký và kiểm tra giá hiển thị trên App Store trước khi thanh toán.
   ------ Nhớ vào hủy gia hạn ở phần Đăng ký trong Cài đặt Apple ID nếu chỉ dùng thử / không muốn tự gia hạn -------
