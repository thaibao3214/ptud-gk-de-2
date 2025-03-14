# Thông tin cá nhân:
## Họ Tên : Nguyễn Đặng Thái Bảo
## MSSV: 22002605
# Cài đặt
## Clone repo
- git clone https://github.com/thaibao3214/ptud-gk-de-2.git
- cd ptud-gk-de-2
## Tạo môi trường ảo
- python -m venv venv
- venv\Scripts\activate #kích hoạt với window
- source venv/bin/activate #kích hoạt vơi MacOS/Linux
## Tải các thư viện cần thiết:
- pip install -r requirements.txt
## tạo cơ sở dũ liệu:
- flask db init
- flask db migrate -m "Initial migration"
- flask db upgrade
# Chạy ứng dụng:
- flask run
# Chức năng:
- Đăng ký / đăng nhập / đăng xuất
- Quản lý công việc
- Chỉnh sửa, xóa
- Admin khóa, mở, xóa user





