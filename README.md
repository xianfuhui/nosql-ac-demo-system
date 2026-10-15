# Hệ thống Quản lý Giáo dục — minh họa Access Control trên NoSQL

Ứng dụng web Node.js (Express + EJS) + MongoDB (Mongoose), xây dựng theo bảng chức năng
áp dụng bài báo **"Access Control on NoSQL Databases"** (NIST IR 8504), gồm:

- Xác thực & phân quyền RBAC/ABAC (admin / giảng viên / sinh viên)
- Quản lý tài khoản, môn học, lớp học, hồ sơ sinh viên, điểm (có lịch sử sửa), tài liệu
- Bộ máy kiểm soát truy cập dạng **đồ thị thuộc tính** (subject attribute → action → object attribute),
  lưu trực tiếp trong MongoDB — đúng tinh thần §3.2.3 của bài báo
- Chống NoSQL Injection, ghi nhật ký (audit log) mọi thao tác quan trọng
- AI hỗ trợ tạo quy tắc phân quyền từ văn bản tiếng Việt (Gemini API, §4.8)
- **Trang Kịch bản Demo**: chạy 10 kịch bản kiểm thử THẬT trên dữ liệu MongoDB thật,
  mỗi kịch bản ghi rõ mục tương ứng trong bài báo, input, các bước thực hiện,
  kết quả mong đợi/thực tế, trạng thái đạt/không đạt

## 1. Yêu cầu hệ thống

- Node.js ≥ 18
- MongoDB (một trong các cách sau):
  - Cài MongoDB Community Server chạy local (khuyến nghị để có dữ liệu thật, bền vững)
  - Hoặc dùng MongoDB Atlas (cloud, có gói miễn phí)
  - Hoặc không cấu hình gì cả — hệ thống sẽ tự dùng MongoDB in-memory để chạy thử
    nhanh (xem mục 4). Lưu ý: in-memory cần tải một binary MongoDB qua Internet,
    nếu máy bạn có mạng bình thường (không bị chặn như môi trường sandbox đã dùng
    để phát triển) thì cách này hoạt động tốt.

## 2. Cài đặt

```bash
cd edu-nosql-ac
npm install
cp .env.example .env
```

Mở `.env` và chỉnh `MONGODB_URI` nếu bạn dùng MongoDB thật, ví dụ:

```
MONGODB_URI=mongodb://127.0.0.1:27017/edu_nosql_ac
```

Nếu để nguyên `.env.example` (không có MongoDB), hệ thống sẽ tự dùng MongoDB in-memory —
tiện để chạy thử nhanh nhưng **dữ liệu sẽ mất khi tắt server**.

## 3. Tạo dữ liệu mẫu

```bash
npm run seed
```

Lệnh này tạo sẵn 6 tài khoản demo (mật khẩu đều là `123456`):

| Username  | Vai trò     | Ghi chú                                  |
|-----------|-------------|-------------------------------------------|
| admin1    | admin       | Quản trị viên                              |
| gv_toan   | giangvien   | Phụ trách lớp "Giải tích 1 - Nhóm 1"       |
| gv_van    | giangvien   | Phụ trách lớp "Văn học VN - Nhóm 1"        |
| sv_an     | sinhvien    | Học lớp Giải tích 1                        |
| sv_binh   | sinhvien    | Học lớp Giải tích 1                        |
| sv_chau   | sinhvien    | Học lớp Văn học VN                         |

cùng 2 môn học, 2 lớp học, vài bản ghi điểm, tài liệu, 5 chính sách phân quyền ABAC (collection
`policies`) **và một đồ thị thật** (collection `graphnodes`/`graphedges`) minh họa mô hình Graph
của bài báo (§3.2.3) — dùng riêng cho kịch bản demo #10.

**Lưu ý:** nếu dùng chế độ MongoDB in-memory, server sẽ **tự động seed lại dữ liệu mỗi lần khởi động**
(vì CSDL in-memory không tồn tại lâu dài), nên bước `npm run seed` là tùy chọn trong trường hợp đó.
Nếu dùng MongoDB thật, chạy `npm run seed` một lần để khởi tạo (chạy lại sẽ xóa và tạo lại dữ liệu mẫu).

## 4. Chạy ứng dụng

```bash
npm start
```

Mở trình duyệt tại **http://localhost:3000**, đăng nhập bằng một trong các tài khoản demo
ở trang đăng nhập (có nút "Đăng nhập nhanh" cho từng tài khoản — mỗi lần dùng nút khác nhau
sẽ là một phiên đăng nhập riêng, tiện để minh họa nhiều vai trò cùng lúc trên các trình duyệt/tab khác nhau).

## 5. Trang Kịch bản Demo

Đăng nhập bằng `admin1`, vào mục **"Kịch bản Demo"** ở sidebar. Trang này:

- Chạy trực tiếp trên dữ liệu MongoDB thật (không giả lập)
- Mỗi kịch bản ghi rõ mục/hình trong bài báo mà nó minh họa (tham chiếu chính xác §2, §3.1,
  §3.2.2, §3.2.3 Fig.9-10, §4.1, §4.2, §4.4, §4.6, §4.8 — xem bảng bên dưới)
- Kết quả hiển thị bằng **dữ liệu thật**: bảng document thật, bảng so sánh trước/sau (diff),
  cây phân cấp document, sơ đồ node-edge của đồ thị thật — không mô tả bằng câu văn
- Kịch bản #10 duyệt (BFS) một collection đồ thị thật (`graphnodes`/`graphedges`), tách biệt
  hoàn toàn khỏi collection `policies` dùng ở các kịch bản khác, để minh họa đúng cơ chế
  "nhúng luật phân quyền trực tiếp vào cạnh đồ thị" mà bài báo mô tả ở Fig. 10

| # | Kịch bản | Mục bài báo |
|---|----------|-------------|
| 1 | Truy cập hợp lệ | §3.2.2 Access Control Rules (Document Model) |
| 2 | Truy cập trái phép | §4.2 Security — backdoor access to other users' data |
| 3 | Phân quyền chi tiết (FGAC) | §4.1 Fine-Grained Access Control |
| 4 | Kiểm soát quyền sửa điểm | §3.2.2 · §4.1 áp dụng cho hành động update |
| 5 | Kiểm tra NoSQL Injection | §4.2 Security — injection attacks ($where/$ne) |
| 6 | Kiểm tra nhật ký | §4.6 Audit |
| 7 | AI hỗ trợ tạo quy tắc | §4.8 Support for AI |
| 8 | Thay đổi chính sách & tính nhất quán | §4.4 Data Consistency |
| 9 | Minh họa mô hình dữ liệu NoSQL | §2 Overview · §3.1 Relationship Structures (Fig. 3, 5) |
| 10 | Phân quyền trên dữ liệu dạng đồ thị | §3.2.3 Graph Model (Fig. 9, 10) |

## 6. Chức năng AI hỗ trợ tạo quy tắc phân quyền (§4.8)

Vào mục "AI hỗ trợ quy tắc" (chỉ Admin thấy), nhập Gemini API key vào ô riêng
(hoặc đặt sẵn biến `GEMINI_API_KEY` trong `.env`), sau đó nhập quy định bằng tiếng Việt,
ví dụ:

> "Giảng viên khoa CNTT chỉ được sửa điểm của sinh viên trong lớp mình phụ trách.
> Sinh viên chỉ được xem điểm của chính mình."

AI sẽ phân tích và đề xuất các quy tắc phân quyền dạng cấu trúc (ABAC), Admin xem lại,
chọn quy tắc muốn áp dụng rồi bấm xác nhận mới thực sự ghi vào hệ thống.

## 7. Cấu trúc thư mục

```
edu-nosql-ac/
├── app.js                   # Điểm khởi động ứng dụng
├── config/db.js              # Kết nối MongoDB (thật hoặc in-memory fallback)
├── models/                   # Mongoose schemas (User, MonHoc, LopHoc, Diem, Policy...)
├── middleware/                # auth.js (RBAC), sanitize.js (chống NoSQL Injection)
├── utils/accessControl.js    # Bộ máy kiểm soát truy cập ABAC dạng đồ thị
├── utils/demoScenarios.js    # Logic của 10 kịch bản demo
├── routes/                   # Một file route cho mỗi nhóm chức năng
├── views/                    # Giao diện EJS
├── seed/                     # Script tạo dữ liệu mẫu
└── public/css/style.css      # Giao diện
```

## 8. Về chính sách phân quyền (Policy)

Mục "Chính sách phân quyền" (chỉ Admin) cho phép xem/thêm/sửa/xóa các quy tắc ABAC.
Mỗi chính sách là một "đường đi":

```
(vai trò chủ thể, phạm vi) --[can <action>]--> (loại tài nguyên, khoa)
```

ví dụ: `(giangvien, scope=assigned) --[can update]--> (diem)` nghĩa là
"giảng viên chỉ được sửa điểm của các lớp mình được phân công" — đúng mô hình
đồ thị thuộc tính Fig. 9–10 trong bài báo.

## 9. Ghi chú triển khai thật

- Để triển khai thật, đổi `SESSION_SECRET` trong `.env`, dùng MongoDB thật (không dùng in-memory),
  và cân nhắc dùng HTTPS + `cookie.secure = true` cho session.
- Tính năng "Quản lý tài liệu" ở bản demo lưu nội dung dạng văn bản thay vì upload file thật,
  để tập trung minh họa access control thay vì xử lý file.
