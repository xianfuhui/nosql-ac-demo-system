# NoSQL-ACL (theo NIST IR 8504)
Chạy: `cp .env.example .env` (điền GEMINI_API_KEY, đổi mật khẩu) → `npm install` → `npm start` → http://localhost:3000
Cần Node >= 20.6. Không có GEMINI_API_KEY vẫn chạy, dùng luật heuristic.

## Cập nhật
- **Nạp dữ liệu**: chọn 0–3 trước, ô nhập của cách đó mới hiện ra.
- **Sơ đồ (Tổng quan, Hình 5–10) và Hình 1–4**: mỗi nhánh chỉ hiện vài nút, phần còn lại gộp thành nút “…” (viền vàng). Bấm vào để chọn nút cần hiển thị trong modal; nút bắt buộc (gốc, nút thuộc luật đang vẽ) luôn hiện. Hình 5 dùng bố cục cây theo cấp.
- **Hình 1–4**: dạng NoSQL đang dùng nằm riêng một dòng, căn giữa; giá trị dài được cắt gọn, không tràn khỏi khung.
- **Xuất phân quyền** (tab mới): tải bộ luật đã duyệt dưới dạng `acl-policy.json`, `acl-policy.csv` hoặc `acl-engine.js` (bộ luật + hàm `check`/`decide`, dùng được ngay trong hệ thống Node). API: `GET /api/export?format=json|csv|js`.
