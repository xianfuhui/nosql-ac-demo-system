# NoSQL-ACL (theo NIST IR 8504)
Chạy: `cp .env.example .env` (điền GEMINI_API_KEY, đổi mật khẩu) → `npm install` → `npm start` → http://localhost:3000
Cần Node >= 20.6. Không có GEMINI_API_KEY vẫn chạy, dùng luật heuristic.

## Cập nhật
- **Nạp dữ liệu**: chọn 0–3 trước, ô nhập của cách đó mới hiện ra.
- **Xuất phân quyền** (tab mới): tải bộ luật đã duyệt dưới dạng `acl-policy.json`, `acl-policy.csv` hoặc `acl-engine.js` (bộ luật + hàm `check`/`decide`, dùng được ngay trong hệ thống Node). API: `GET /api/export?format=json|csv|js`.
- **Gemini API key**: ô nhập nằm ngay trên phần "Nạp dữ liệu" (tab Nạp dữ liệu). Dán key, chọn model, bấm "Lưu & kiểm tra" (server gọi thử Gemini trước khi nhận). Key chỉ lưu trong bộ nhớ máy chủ, không ghi vào `state.json`, giao diện chỉ hiện 4 ký tự cuối. Bấm "Xoá key" để quay về key trong `.env` (nếu có) hoặc luật heuristic. API: `POST /api/gemini-key {key, model}`, `DELETE /api/gemini-key`.

- **Tổng quan** chỉ hiển thị dữ liệu đang nạp (nếu là mẫu thì ghi rõ mẫu nào). **4 kiểu NoSQL** (trước đây là Hình 1–4): kiểu đang dùng nằm riêng một dòng, căn giữa; nút “…” (viền vàng) gộp phần còn lại, bấm để chọn nút cần hiển thị. Đã bỏ mục Hình 5–10.