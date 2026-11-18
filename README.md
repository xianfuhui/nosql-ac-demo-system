# NoSQL-ACL (theo NIST IR 8504)
Chạy: `cp .env.example .env` (điền GEMINI_API_KEY, đổi mật khẩu) → `npm install` → `npm start` → http://localhost:3000
Cần Node >= 20.6. Không có GEMINI_API_KEY vẫn chạy, dùng luật heuristic.

## Cập nhật
- **Nạp dữ liệu**: chọn 0–3 trước, ô nhập của cách đó mới hiện ra.
- **Xuất phân quyền** (tab mới): tải bộ luật đã duyệt dưới dạng `acl-policy.json`, `acl-policy.csv` hoặc `acl-engine.js` (bộ luật + hàm `check`/`decide`, dùng được ngay trong hệ thống Node). API: `GET /api/export?format=json|csv|js`.
- **Gemini API key**: ô nhập nằm ngay trên phần "Nạp dữ liệu" (tab Nạp dữ liệu). Dán key, chọn model, bấm "Lưu & kiểm tra" (server gọi thử Gemini trước khi nhận). Key chỉ lưu trong bộ nhớ máy chủ, không ghi vào `state.json`, giao diện chỉ hiện 4 ký tự cuối. Bấm "Xoá key" để quay về key trong `.env` (nếu có) hoặc luật heuristic. API: `POST /api/gemini-key {key, model}`, `DELETE /api/gemini-key`.

- **Tổng quan** chỉ hiển thị dữ liệu đang nạp (nếu là mẫu thì ghi rõ mẫu nào). **4 kiểu NoSQL** (trước đây là Hình 1–4): kiểu đang dùng nằm riêng một dòng, căn giữa; nút “…” (viền vàng) gộp phần còn lại, bấm để chọn nút cần hiển thị. Đã bỏ mục Hình 5–10.
- **Benchmark theo dữ liệu đang nạp**: bộ luật chuẩn + ca kiểm thử đi theo dữ liệu bạn nạp (trước đây luôn so với dữ liệu bệnh viện). 3 chế độ:
  - `hospital`: nạp mẫu 🏥 Bệnh viện → dùng 20 luật + 30 ca soạn tay.
  - `auto`: dữ liệu khác (file, URL, Mongo/Redis, mẫu khác) → luật tham chiếu tự sinh từ cấu trúc (admin/editor/user, chặn trường nhạy cảm, chặn xoá) + ca kiểm thử sinh từ luật đó. Chỉ mang tính tham khảo.
  - `custom`: bạn tự nạp ground truth (tab Benchmark → "Bộ chuẩn đánh giá"). API: `GET/POST/DELETE /api/eval/ground-truth`, `GET /api/eval/bench-info`.
  - Nạp dữ liệu mới sẽ tự bỏ ground truth cũ. Benchmark hiệu năng cũng lấy đường dẫn/chủ thể từ dữ liệu đang nạp.

- **Quét database đủ 4 kiểu NoSQL** (Nạp dữ liệu → 3): MongoDB (document) · Redis (key-value) · **Cassandra (wide-column)** `cassandra://user:pass@host:9042/keyspace?dc=datacenter1` · **Neo4j (graph)** `neo4j://user:pass@host:7687/neo4j` (nhận cả `bolt://`, `neo4j+s://`). Cần `npm install` lại (thêm `cassandra-driver`, `neo4j-driver`). Mô hình dữ liệu tự gán theo loại DB.
