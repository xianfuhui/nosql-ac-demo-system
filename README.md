# Sổ điểm

Web Node.js để **tải file hoặc dán link** dữ liệu học sinh, **lưu vào MongoDB**, rồi **trực quan hoá** và **xem hồ sơ theo vai trò** (phân quyền theo trường dữ liệu, theo ý tưởng của NIST IR 8504). Web còn **chạy notebook `.ipynb` trên chính dữ liệu trong MongoDB** và hiển thị đầy đủ kết quả (bảng, biểu đồ, các demo bám theo bài báo).

## Chạy

Cần Node.js 18 trở lên và một MongoDB đang chạy. Muốn chạy lại notebook trên dữ liệu của bạn cần thêm Python 3 với `pandas numpy networkx matplotlib` (`pip install pandas numpy networkx matplotlib`). Không có Python vẫn xem được kết quả mẫu đi kèm.

```bash
npm install
docker compose up -d          # MongoDB 7 ở cổng 27017 (bỏ qua nếu đã có MongoDB)
npm start                     # mở http://localhost:3000
```

Biến môi trường (xem `.env.example`): `PORT`, `MONGODB_URI` (mặc định `mongodb://127.0.0.1:27017`), `MONGODB_DB` (mặc định `so_diem`).
Dùng file `.env`: `node --env-file=.env server.js`.

## Dùng thử nhanh

1. Tab **Dán link**, bấm *Dùng dataset Student Performance của UCI*, rồi *Tải và nhập*.
   Link là `https://archive.ics.uci.edu/static/public/320/student+performance.zip`. Ứng dụng tự giải nén zip (kể cả zip lồng nhau) và lấy `student-mat.csv`.
2. Hoặc tab **Tải file lên**, chọn `sample/sample-synthetic-students.csv` (dữ liệu **tổng hợp**, cùng schema UCI, chỉ để thử khi chưa có mạng).
3. Kéo xuống phần **Hồ sơ theo vai trò**, đổi vai trò và xem các ô bị che thay đổi.

## Định dạng nhập được

CSV/TSV (tự nhận dấu `,` `;` tab `|`, hỗ trợ ô trong nháy kép), JSON (mảng đối tượng hoặc `{data|records|rows|items: [...]}`), ZIP chứa các file trên. Tối đa 50 MB, 100.000 dòng, 200 cột. Mỗi cột tự được nhận là số, phân loại hoặc văn bản.
Link phải trỏ thẳng tới file, không phải trang HTML (trang dataset của UCI sẽ bị từ chối kèm hướng dẫn).

## Dữ liệu trong MongoDB

| Collection | Nội dung |
|---|---|
| `datasets` | tên, nguồn, số dòng, danh sách cột và kiểu |
| `records` | `{datasetId, rid, data:{...}}`, mỗi dòng là một document |
| `policies` | luật truy cập (tự tạo lần chạy đầu, sửa trực tiếp được) |
| `audit` | nhật ký mỗi lần xem hồ sơ: vai trò, số dòng, tỉ lệ ô bị che |

## Liên kết với notebook .ipynb

```
MongoDB  --(Node xuất CSV)-->  Python chạy notebook  --(result.json)-->  Node  -->  trang web
```

Phần **Sổ tay phân tích** ở cuối trang:

1. Luôn có sẵn **kết quả mẫu** (chạy trên dữ liệu tổng hợp) nên xem được ngay, kể cả khi chưa có Python.
2. Bấm **Chạy notebook với dataset này**: Node xuất dataset đang chọn từ MongoDB ra file CSV tạm, gọi `notebook/run_notebook.py`, notebook đọc CSV qua biến môi trường `LOCAL_CSV`. Chạy xong, web hiển thị toàn bộ nội dung: markdown, mã nguồn (đóng/mở), bảng và biểu đồ. File CSV tạm bị xoá ngay sau khi chạy.
3. **Tải notebook gốc** hoặc **Tải bản đã chạy** (có sẵn output, mở được bằng Jupyter/Colab).

Điều kiện: dataset phải có các cột `school, age, G1, G2, G3` (số, trừ `school`), vì notebook viết cho dữ liệu học sinh kiểu UCI. Dataset khác vẫn dùng được các biểu đồ và bảng phân quyền của web.
Mỗi lúc chỉ chạy một notebook, tối đa 5 phút; giữ 6 lần chạy gần nhất trong `notebook/runs/`. Đặt biến `PYTHON` nếu lệnh Python của bạn không phải `python3` (Windows mặc định dùng `python`).
Tạo lại kết quả mẫu: `npm run notebook:example`. Notebook cũng chạy độc lập trong Jupyter/Colab, không cần web.

API: `GET /api/notebook/info`, `POST /api/notebook/run {datasetId}`, `GET /api/notebook/jobs/:id`, `GET /api/notebook/result[?jobId=]`, `GET /api/notebook/download?kind=source|jobId=`.

## Phân quyền (liên hệ bài báo)

- Trường dữ liệu chia thành nhóm `academic`, `personal`, `family`, `other` (xem `lib/acl.js`; cột lạ vào `other`).
- Luật mặc định từ chối. Mỗi luật gồm vai trò, nhóm trường, điều kiện (`trained`, `at_risk`). Deny ghi đè permit.
- Subject có thuộc tính trường học và phải khớp trường học của hồ sơ (object).
- Ô bị che **không rời khỏi server**. Ô tìm kiếm chỉ tìm trong các ô vai trò đó được xem, để không dò ra dữ liệu bị che.

| Vai trò | Được xem | Điều kiện |
|---|---|---|
| Giáo viên | học tập | đã tập huấn bảo mật |
| Tư vấn viên | cá nhân | không |
| Tư vấn viên | học tập | học sinh có G2 < 10 |
| Quản trị | tất cả | không |

**Lưu ý:** vai trò hiện được chọn ngay trên giao diện để minh hoạ, **chưa có đăng nhập**. Khi triển khai thật cần xác thực (session/JWT) và lấy vai trò từ phía server.

## API

```
GET    /api/health
GET    /api/datasets
POST   /api/datasets/upload        multipart: file, name
POST   /api/datasets/url           JSON: {url, name}
DELETE /api/datasets/:id
GET    /api/datasets/:id/stats
GET    /api/datasets/:id/groupby?by=school&metric=G3
GET    /api/datasets/:id/scatter?x=G1&y=G3
GET    /api/datasets/:id/records?role=teacher&school=GP&trained=true&page=1&q=
GET    /api/policies
GET    /api/audit
```

## Bảo mật khi nhập link

Server chặn link tới địa chỉ nội bộ (localhost, 10.x, 192.168.x, 169.254.x…), kiểm tra lại sau mỗi lần chuyển hướng, giới hạn 30 giây và 50 MB. Đặt `ALLOW_PRIVATE_URLS=1` chỉ khi cần thử với máy nội bộ.

## Kiểm thử

```bash
npm test
```

Chạy 30 kiểm thử cho phần đọc file, thống kê, phân quyền, chống SSRF, các route và liên kết notebook (có chạy Python thật qua Node). Các route được thử bằng bản giả lập express/mongodb trong `test/stubs`, nên chạy được cả khi chưa có MongoDB; riêng phần notebook cần Python và các thư viện ở trên.
`node test/preview-server.js` mở bản xem thử giao diện ở cổng 3111 (Chart.js được thay bằng bản rỗng nên biểu đồ để trống).

## Cấu trúc

```
server.js            Express + MongoDB, các route
lib/ingest.js        đọc CSV/JSON/ZIP, suy luận kiểu cột (không phụ thuộc thư viện ngoài)
lib/stats.js         histogram, đếm nhóm, tương quan, groupby, scatter
lib/acl.js           luật ABAC theo trường dữ liệu
lib/fetchurl.js      tải link an toàn (chống SSRF, giới hạn dung lượng)
lib/notebook.js      xuất CSV từ MongoDB, gọi Python chạy notebook, đọc kết quả
public/              index.html, style.css, app.js (Chart.js lấy từ node_modules)
notebook/            notebook .ipynb, run_notebook.py, example/ (kết quả mẫu), runs/ (các lần chạy)
sample/              dữ liệu mẫu tổng hợp
test/                kiểm thử và giả lập
```
