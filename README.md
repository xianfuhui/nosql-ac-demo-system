# NoSQL-ACL (theo NIST IR 8504)
Chạy: `cp .env.example .env` (điền GEMINI_API_KEY, đổi mật khẩu) → `npm install` → `npm start` → http://localhost:3000
Cần Node >= 20.6. Không có GEMINI_API_KEY vẫn chạy, dùng luật heuristic.

## Cập nhật mới nhất (Database hệ thống)
- **Database hệ thống chuyển thành ô riêng, nằm ngay trên "Nạp dữ liệu", ghi rõ "Không bắt buộc"**. Có giải thích khi bỏ trống: không giữ bản sao dữ liệu gốc; chỉ lưu cấu trúc đã phân tích, luật, nhật ký vào `state.json`; kết nối nguồn (cách 3) chỉ ở bộ nhớ.

## Cập nhật trước nữa
- **Database riêng của hệ thống: nhập link ngay trên giao diện** (tab Nạp dữ liệu → "Database hệ thống"), đủ 4 kiểu NoSQL: `mongodb://…` · `redis://…` · `cassandra://…/keyspace` (keyspace phải có sẵn, bảng tự tạo) · `neo4j://…`/`bolt://…`. Bấm Kết nối để thử; thành công thì mọi nguồn nạp (mẫu, file, URL, quét database) được **sao chép vào DB này** rồi hệ thống **đọc lại từ đó** để phân tích; benchmark cũng chạy trên DB này. Link chỉ giữ trong bộ nhớ (có mật khẩu), mỗi lần khởi động lại cần nhập lại, hoặc đặt sẵn `MONGO_URI=mongodb://localhost:27017/nosql` trong `.env`. Đổi sang DB khác thì phải nạp lại dữ liệu. Chưa có DB hệ thống thì chạy như trước (dữ liệu chỉ ở bộ nhớ). Quét nguồn ngoài vẫn chỉ sao chép phần mẫu (vài bản ghi/bảng, tối đa 12 bảng). Bố cục lưu: Mongo `_datasets` + `ds_<tên>__<phần>`; Redis `acl:ds:<tên>:*`; Cassandra bảng `acl_meta`/`acl_rows`; Neo4j node `AclDataset`/`AclRow`.
- **Tổng quan: ghi rõ các tầng** (theo Fig. 5, Sec. 3.1 của NIST IR 8504). Phía trên hình có bảng 5 tầng: Tầng 1 `Key-value database / Wide column database / Document database` · Tầng 2 `Tables / Column families / Collections` · Tầng 3 `Keys / Rows / Documents` · Tầng 4 `Values / Column ID / Fields` · Tầng 5 `Null / Values / Values`. Tầng của mô hình đang nạp **in đậm** (ví dụ nạp Document thì *Documents* đậm). Hình vẽ cũng có nhãn "Tầng n · …" ở bên trái từng hàng nút. Mô hình Graph không chia tầng nên chỉ hiện lời giải thích.
- **Nhật ký chỉ ghi "Kiểm tra truy cập"** (§4.6). Đã bỏ ghi đăng nhập, nạp dữ liệu, sửa/duyệt luật, xuất file, đổi API key, chat, benchmark, bộ lọc injection. Mỗi dòng gồm: thời gian · chủ thể · đối tượng · hành động · môi trường · kết quả · luật quyết định. `state.json` cũ tự được dọn khi khởi động: chỉ giữ các dòng `check`, đổi sang cấu trúc mới. Lưu ý: tiêu chí "Ghi nhật ký" ở tab Đánh giá chỉ đạt khi đã có ít nhất một lượt kiểm tra.
- **Bỏ tab "Bảo mật" (khung thử bộ lọc injection)**. Bộ lọc injection thật (`guard`, NIST IR 8504 §4.2) vẫn áp dụng cho mọi request tới `/api` như trước — chỉ bỏ trang demo cho người dùng tự nhập chuỗi để thử; tiêu chí "Bộ lọc chống NoSQL injection" ở tab Đánh giá vẫn chấm điểm bộ lọc này.
- **Xuất phân quyền: sơ đồ cách dùng** trong hệ thống chính (xuất file → đặt vào dự án → middleware `acl.check()` → cho phép / 403) và 3 quy tắc quyết định (deny thắng grant · mặc định từ chối).

## Cập nhật trước đó
- **Nạp dữ liệu**: chọn 0–3 trước, ô nhập của cách đó mới hiện ra.
- **Xuất phân quyền** (tab mới): tải bộ luật đã duyệt dưới dạng `acl-policy.json`, `acl-policy.csv` hoặc `acl-engine.js` (bộ luật + hàm `check`/`decide`, dùng được ngay trong hệ thống Node). API: `GET /api/export?format=json|csv|js`.
- **Gemini API key**: ô nhập nằm ngay trên phần "Nạp dữ liệu" (tab Nạp dữ liệu). Dán key, chọn model, bấm "Lưu & kiểm tra" (server gọi thử Gemini trước khi nhận). Key chỉ lưu trong bộ nhớ máy chủ, không ghi vào `state.json`, giao diện chỉ hiện 4 ký tự cuối. Bấm "Xoá key" để quay về key trong `.env` (nếu có) hoặc luật heuristic. API: `POST /api/gemini-key {key, model}`, `DELETE /api/gemini-key`.

- **Tổng quan** chỉ hiển thị dữ liệu đang nạp (nếu là mẫu thì ghi rõ mẫu nào). **4 kiểu NoSQL** (trước đây là Hình 1–4): kiểu đang dùng nằm riêng một dòng, căn giữa; nút “…” (viền vàng) gộp phần còn lại, bấm để chọn nút cần hiển thị. Đã bỏ mục Hình 5–10.
- **Đánh giá (trước là Benchmark) theo dữ liệu đang nạp**: bộ luật chuẩn + ca kiểm thử đi theo dữ liệu bạn nạp (trước đây luôn so với dữ liệu bệnh viện). 3 chế độ:
  - `hospital`: nạp mẫu 🏥 Bệnh viện → dùng 20 luật + 30 ca soạn tay.
  - `auto`: dữ liệu khác (file, URL, Mongo/Redis, mẫu khác) → luật tham chiếu tự sinh từ cấu trúc (admin/editor/user, chặn trường nhạy cảm, chặn xoá) + ca kiểm thử sinh từ luật đó. Chỉ mang tính tham khảo.
  - `custom`: bạn tự nạp ground truth (tab Đánh giá → "Bộ chuẩn đánh giá"). API: `GET/POST/DELETE /api/eval/ground-truth`, `GET /api/eval/bench-info`.
  - Nạp dữ liệu mới sẽ tự bỏ ground truth cũ. Benchmark hiệu năng cũng lấy đường dẫn/chủ thể từ dữ liệu đang nạp.

- **Quét database đủ 4 kiểu NoSQL** (Nạp dữ liệu → 3): MongoDB (document) · Redis (key-value) · **Cassandra (wide-column)** `cassandra://user:pass@host:9042/keyspace?dc=datacenter1` · **Neo4j (graph)** `neo4j://user:pass@host:7687/neo4j` (nhận cả `bolt://`, `neo4j+s://`). Cần `npm install` lại (thêm `cassandra-driver`, `neo4j-driver`). Mô hình dữ liệu tự gán theo loại DB.

- **Cấu trúc source**: dữ liệu tách khỏi `server.js` vào thư mục `data/` — `data/samples.js` (4 mẫu keyvalue/wide/document/graph), `data/hospital.js` (dữ liệu Bệnh viện + 20 luật chuẩn `HOSPITAL_GT` + 30 ca kiểm thử `HOSPITAL_TESTS`). Muốn thêm dataset mẫu mới, tạo file mới trong `data/` rồi `require` ở `server.js`.
- **Model & phiên bản API Gemini tự nhập**: ô model và ô phiên bản API (`v1beta`, `v1`, `v1alpha`…) đều gõ tự do được (có gợi ý sẵn). Mặc định `v1beta`; đặt mặc định qua `GEMINI_API_VERSION` trong `.env`. API: `POST /api/gemini-key {key, model, ver}`.

- **Đổi tên & sắp xếp lại tab**: "Đánh giá & bảo mật" → **🛡️ Bảo mật** (chỉ còn thử NoSQL injection, gắn nhãn NIST IR 8504 §4.2). "Benchmark" → **📊 Đánh giá**, thứ tự: Bộ chuẩn → ① Tuân thủ NIST IR 8504 (có nhãn `NIST IR 8504` và thẻ § từng tiêu chí, tự chạy khi mở tab) → ② Độ chính xác chuyển đổi luật → ③ Soạn luật thủ công vs AI → ④ Độ chính xác quyết định → ⑤ Tốc độ truy vấn.
