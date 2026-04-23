CÔNG CỤ KHAI THÁC SQL INJECTION
================================

TỔNG QUAN
---------
Công cụ khai thác SQL Injection được viết bằng C++ cho Windows (Visual Studio 2022). Tự động phát hiện và khai thác lỗ hổng SQL injection trong ứng dụng web, tương tự như SQLMap nhưng viết bằng C++ thuần với Winsock2.

TÍNH NĂNG
---------
- 4 kỹ thuật phát hiện SQL injection (Boolean, Time, Error, Union)
- Tự động liệt kê cơ sở dữ liệu (schema, bảng, cột, dữ liệu)
- Hỗ trợ HTTP (HTTPS chuyển sang port 80)
- Hỗ trợ phương thức GET và POST
- Hỗ trợ Cookie và header tùy chỉnh
- Xoay vòng proxy với tự động tải danh sách proxy
- Xử lý đa luồng
- Xuất debug chi tiết
- Độ trễ request có cấu hình
- Ghi log đầy đủ ra file

KỸ THUẬT PHÁT HIỆN
------------------
1. Boolean-based blind SQL injection
2. Time-based blind SQL injection  
3. Error-based SQL injection
4. Union-based SQL injection

CƠ SỞ DỮ LIỆU HỖ TRỢ
---------------------
- MySQL
- PostgreSQL
- Microsoft SQL Server (MSSQL)
- Oracle
- SQLite

YÊU CẦU HỆ THỐNG
----------------
- Windows 10/11
- Visual Studio 2022

CÀI ĐẶT
-------
1. Mở Visual Studio 2022
2. Tạo Console App (C++)
3. Copy toàn bộ mã nguồn vào file .cpp
4. Cấu hình: Project -> Properties -> Linker -> Input -> Additional Dependencies -> thêm ws2_32.lib
5. Build -> Build Solution

CÁCH SỬ DỤNG
------------
Cú pháp:
  tool.exe -u <URL> [tùy chọn]

Tùy chọn:
  -u <url>              URL mục tiêu (bắt buộc)
  --data=<data>         Dữ liệu POST (dùng [INJECT] làm điểm chèn)
  --cookie=<c>          Cookie HTTP
  --proxy               Bật xoay vòng proxy
  --delay=<ms>          Độ trễ giữa các request (ms)
  --verbose             Xuất debug chi tiết

VÍ DỤ
-----
1. GET parameter:
   tool.exe -u "http://testphp.vulnweb.com/artists.php?id=1"

2. POST data:
   tool.exe -u "http://test.com/login.php" --data="user=admin&pass=[INJECT]"

3. Với cookie:
   tool.exe -u "http://test.com/page.php?id=1" --cookie="session=abc123"

4. Bật proxy:
   tool.exe -u "http://test.com/page.php?id=1" --proxy

5. Độ trễ 500ms:
   tool.exe -u "http://test.com/page.php?id=1" --delay=500

6. Chế độ debug:
   tool.exe -u "http://test.com/page.php?id=1" --verbose

QUY TRÌNH QUÉT
--------------
1. Lấy response baseline
2. Gửi payload kiểm tra lỗ hổng
3. Phát hiện kỹ thuật khai thác phù hợp
4. Trích xuất thông tin:
   - Tên database hiện tại
   - Phiên bản database
   - Người dùng hiện tại
   - Danh sách databases
   - Danh sách bảng
   - Danh sách cột
   - Dữ liệu từ các bảng

PROXY
-----
Công cụ tự động tải danh sách proxy từ các nguồn:
- TheSpeedX PROXY-List
- ShiftyTR Proxy-List  
- monosans proxy-list

Sau đó kiểm tra proxy hoạt động và tự động xoay vòng khi gửi request.

KẾT QUẢ
-------
- Màn hình: Hiển thị chi tiết quá trình quét và dữ liệu trích xuất
- File log: sqlmap_log.txt (lưu toàn bộ lịch sử)

ĐỌC KẾT QUẢ
-----------
[*] - Thông tin
[+] - Thành công
[-] - Lỗi
[!!!] - Lỗ hổng
[DEBUG] - Debug (cần --verbose)

VÍ DỤ OUTPUT
------------
========================================
  SQL INJECTION EXPLOITATION TOOL
  Version 3.0
========================================

[*] Target: testphp.vulnweb.com:80/artists.php?id=1
[*] Method: GET
[*] Getting baseline...
[+] Baseline: 4523 bytes, 234ms
[*] Loaded 12 payloads
[*] Scanning for SQL injection...
[!!!] SQL INJECTION CONFIRMED!
[+] Target: testphp.vulnweb.com:80
[+] Technique: Union-based
[+] DB Type: MySQL
[+] Getting current user...
[+] User: root@localhost
[+] Getting database version...
[+] Version: 5.7.33
[+] Getting database name...
[+] Database: acuart
[+] Getting all databases...
[+] DB: acuart
[+] DB: information_schema
[*] Getting tables from acuart...
[+] Table: artists
[+] Table: products
[+] Table: users

========================================
Table: acuart.users
========================================
1|admin|admin@test.com|5f4dcc3b5aa765d61d8327deb882cf99
2|user|user@test.com|5f4dcc3b5aa765d61d8327deb882cf99
========================================

[+] Exploitation complete!
[*] Total requests: 156

XỬ LÝ SỰ CỐ
-----------
1. Không kết nối được:
   - Kiểm tra URL
   - Kiểm tra tường lửa
   - Kiểm tra kết nối mạng

2. Winsock failed:
   - Chạy với quyền Administrator
   - Kiểm lại cấu hình project (ws2_32.lib)

3. Không tìm thấy proxy:
   - Kiểm tra kết nối internet
   - Tắt tường lửa tạm thời
   - Dùng --proxy mà không cần proxy vẫn chạy được

GIỚI HẠN
--------
- HTTPS không được hỗ trợ đầy đủ (chuyển sang HTTP port 80)
- Chưa hỗ trợ xác thực NTLM
- Proxy chỉ hỗ trợ HTTP (không SOCKS)

CẢNH BÁO
--------
Công cụ này chỉ dùng để kiểm tra bảo mật trên hệ thống được ủy quyền. 
Sử dụng trái phép là vi phạm pháp luật.
