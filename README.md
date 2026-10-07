# 🎬 KỊCH BẢN DEMO — Access Control on NoSQL Databases
## NIST IR 8504 | Node.js + MongoDB

---

## ⏱️ Thời gian: ~20-25 phút | Cấu trúc: 8 màn demo

---

## 🎯 MỞ ĐẦU (1 phút)

> **Người thuyết trình nói:**
> "Bài báo NIST IR 8504 nghiên cứu vấn đề kiểm soát truy cập trên hệ thống NoSQL.
> Hệ thống demo này minh họa trực tiếp từng section của bài báo trên nền Node.js + MongoDB."

**Mở trình duyệt → `frontend/index.html`**
Giới thiệu nhanh giao diện: sidebar trái = các section, nội dung phải = demo tương tác.

---

## 🎬 MÀN 1 — Login & User Attributes (2 phút)
**→ Click: Login**

### Bước 1.1 — Login với alice (manager)
- Nhập: `alice` / `alice123` → Login
- Kết quả hiện: **role: manager | dept: Engineering | clearance: 3**

> "Mỗi user có subject attributes theo §3.2 của bài báo:
> role, department, group, organization, clearance.
> Đây là các node trong cây phân cấp (Fig.5)."

### Bước 1.2 — Thử các user khác
- Click **guest** → clearance: 0, role: guest
- Click **admin** → clearance: 5, role: admin

> "Ta sẽ thấy cùng một resource, các user khác nhau cho kết quả khác nhau."

---

## 🎬 MÀN 2 — §2: 4 Loại NoSQL Model (3 phút)
**→ Click: §2 - 4 Models**

### Bước 2.1 — Giới thiệu 4 model
- Trang load 4 card: Key-Value, Wide-Column, Document, Graph
- **Click vào từng card** → hiện cấu trúc dữ liệu + MongoDB simulation

> "§2.1 mô tả 4 loại NoSQL. Mỗi loại có cấu trúc khác nhau
> dẫn đến thách thức access control khác nhau."

| Model | Cấu trúc | AC Challenge |
|---|---|---|
| Key-Value | key → value | Chỉ check được ở Table level |
| Wide-Column | column family → row → column | Cần mở rộng cây ngang |
| Document | collection → document → field | Field-level cần add-on |
| Graph | node → edge | Linh hoạt nhất, nhúng rule trực tiếp |

### Bước 2.2 — Table 1: RDBMS vs NoSQL
- Kéo xuống xem bảng so sánh

> "Điểm quan trọng: NoSQL chọn AP trong CAP theorem,
> đánh đổi Consistency để lấy Availability — ảnh hưởng trực tiếp đến AC (§4.4)."

---

## 🎬 MÀN 3 — §3: Tạo Access Control Policy (4 phút)
**→ Click: §3 - Policy Builder**

### Bước 3.1 — Xem policies có sẵn
- Scroll xuống xem bảng policies đã seed
- Click filter: **Document** → chỉ thấy policies cho document model

> "Mỗi policy là một rule theo format §3.2:
> {subject attributes} + {object attributes} + {actions} + {effect}"

### Bước 3.2 — Tạo policy mới (Wide-Column model)
Điền form:
- **Name:** `IoT data - only operations team`
- **NoSQL Model:** `Wide-Column`
- **Type:** `ABAC`
- **Effect:** `Allow`
- **Actions:** `read`
- **Subject:** role=`employee`, department=`Operations`
- **Object:** division=`Operations`, classification=`internal`

→ Click **"Generate Rule Text"**

> "Hệ thống tự sinh ngôn ngữ tự nhiên theo §3.2.2:
> 'employees in department Operations can read objects of division Operations'"

→ Click **"Create Policy"**

> "Policy được lưu vào MongoDB, sẵn sàng để AC engine evaluate."

---

## 🎬 MÀN 4 — §3.3: Evaluate Access Request (3 phút)
**→ Click: ⚡ Evaluate Request**

### Bước 4.1 — Chạy 4 scenarios có sẵn
Click lần lượt từng nút:

**Scenario 1:** Employee reads public → **✅ ALLOW**
> "Policy 'Public resources - any user' match → allow"

**Scenario 2:** Guest reads internal → **🚫 DENY**
> "Policy 'Deny guest access to internal' match (priority 80) → deny trước"

**Scenario 3:** Manager writes confidential → **✅ ALLOW**
> "Policy 'Manager write access' match"

**Scenario 4:** Employee reads secret → **🚫 DENY**
> "Clearance 2 < threshold → denied by MAC policy"

### Bước 4.2 — Test thủ công
Chỉnh subject: role=`guest`, clearance=`0`
Object: classification=`secret`
Action: `read` → **DENY**

Đổi role=`admin` → **ALLOW**

> "AC engine §3.3 đánh giá theo deny-overrides:
> nếu có policy DENY match → deny ngay dù có ALLOW."

---

## 🎬 MÀN 5 — §3.2.3: Graph Model (3 phút)
**→ Click: 🕸️ Graph AC**

### Bước 5.1 — Xem Graph Visualization
- Click **"Load Graph"**
- Giải thích màu sắc:
  - 🔵 **Xanh dương** = Subject nodes (user)
  - 🟠 **Cam** = Object nodes (file, collection)
  - 🟣 **Tím** = Attribute nodes (group, company, department)
  - **Nét đứt đỏ** = Action edges = AC rule được nhúng trực tiếp

> "§3.2.3 Fig.9: Attributes được mô tả qua chuỗi nodes + edges.
> alice (node) → in (edge) → dev-team (node) → works_for (edge) → TechCorp (node)"

> "§3.2.3 Fig.10: Edge có thể là permitted action.
> Thay vì lưu rule bên ngoài, rule được nhúng thẳng vào graph!"

### Bước 5.2 — Check Access qua Graph Path
- Subject: `user:alice` | Object: `file:report-q4` | Action: `read`
- Click **Check Access** → **✅ ALLOW** + path hiện

- Đổi Subject: `user:bob` | Object: `file:financial-data` | Action: `read`
- → **🚫 DENY** (không có path)

> "Graph AC tìm đường đi từ subject đến object.
> Nếu có edge 'can_read' → allow, không có path → deny."

---

## 🎬 MÀN 6 — §4.1 + §4.2: FGAC & Security (2 phút)

### §4.1 FGAC
**→ Click: §4.1 FGAC**

> "§4.1: NoSQL thiếu FGAC tích hợp sẵn.
> RDBMS có 6 levels (down to cell), NoSQL chỉ có 4-5 levels."

Xem bảng granularity levels:
- Document model: database → collection → document → **field** (cần add-on)
- RDBMS: database → schema → table → row → **column → cell** ✓

### §4.2 Security — Injection Demo
**→ Click: §4.2 Security**

- Thử input: **Normal** `alice` → Safe ✅
- Thử input: **Object injection** `{"$gt":""}` → 🚨 MALICIOUS DETECTED
- Thử input: **$where injection** → 🚨 MALICIOUS DETECTED

> "§4.2: NoSQL dễ bị injection qua object operator như $gt, $where.
> Khác SQL injection nhưng nguy hiểm tương đương."

---

## 🎬 MÀN 7 — §4.4 + §4.6: Consistency & Audit (2 phút)

### §4.4 CAP Theorem
**→ Click: §4.4 Consistency**

> "NoSQL chọn AP → bỏ Consistency.
> Với AC: nếu role user bị revoke trên node A nhưng chưa sync sang node B
> → node B vẫn cho phép access trong window đồng bộ."

Highlight impact:
- RBAC: ⚠️ Affected (role assignment có thể chưa sync)
- ABAC: ⚠️ Affected (attribute values khác nhau giữa nodes)
- DAC: ✅ Less affected

### §4.6 Audit Log
**→ Click: §4.6 Audit**

- Dashboard hiện: Total / Allow / Deny / Deny Rate
- Bảng log chi tiết: user, action, resource, decision, policy matched

> "§4.6: Mỗi access attempt đều được log — user, action, resource,
> policy nào đã quyết định, và lý do. Đây là các requests từ các bước demo trên."

---

## 🎬 MÀN 8 — §4.8: AI NLP → Formal AC Rule (3 phút)
**→ Click: 🤖 §4.8 AI → Rule**

### Bước 8.1 — Thử mẫu tiếng Việt
Click **"Mẫu 1"**:
> *"Nhân viên phòng Kỹ thuật có cấp độ clearance từ 2 trở lên được phép đọc tài liệu nội bộ thuộc phòng Engineering"*

→ Click **"Parse with AI"**

Kết quả AI trả về JSON:
```json
{
  "subjectConditions": { "department": "Engineering", "minClearance": 2 },
  "objectConditions":  { "division": "Engineering", "classification": "internal" },
  "actions": ["read"],
  "effect": "allow",
  "nosqlModel": "document",
  "confidence": 0.92
}
```

> "§4.8: AI NLP đọc văn bản tự nhiên → nhận diện subject/object/action
> → sinh formal AC rule theo format §3.2."

### Bước 8.2 — Tạo policy trực tiếp
→ Click **"Create this Policy in MongoDB"**

> "Rule được lưu vào MongoDB ngay lập tức, sẵn sàng enforce!"

### Bước 8.3 — Thử nhập tự do
Nhập văn bản tự do:
> *"Chỉ admin mới được xóa dữ liệu tài chính bí mật"*

→ AI parse → tạo policy

---

## 🏁 KẾT THÚC (1 phút)

> **Tóm tắt:**
> - §2: Minh họa 4 loại NoSQL model với dữ liệu thực trong MongoDB
> - §3: Policy Builder tạo AC rules, evaluate theo ABAC/RBAC engine
> - §3.2.3: Graph model nhúng AC rule trực tiếp vào edges
> - §4.1: NoSQL thiếu FGAC tích hợp sẵn, cần add-on
> - §4.2: Dễ bị injection, cần validate input
> - §4.4: Eventual consistency ảnh hưởng đến tính chính xác của AC
> - §4.6: Audit log mọi access attempt
> - §4.8: AI có thể tự động parse văn bản → sinh AC rule

---

## 💡 CÂU HỎI DỰ KIẾN & TRẢ LỜI

**Q: Tại sao dùng MongoDB để demo các model khác (Key-Value, Wide-Column)?**
> A: MongoDB mô phỏng tất cả 4 model thông qua cách tổ chức collections.
> Key-Value = collection {_id, value}, Wide-Column = collection với nhiều fields.
> Thực tế production dùng Redis (KV), Cassandra (WC), Neo4j (Graph).

**Q: ABAC engine có scale được không?**
> A: Demo dùng in-memory evaluation. Production cần cache policies,
> index attributes, dùng policy engine như OPA (Open Policy Agent).

**Q: §4.8 AI có chính xác không?**
> A: Confidence score cho biết độ tin cậy. Cần human review trước khi enforce.
> Đây là hướng nghiên cứu §4.8 đề xuất, chưa phải production-ready.

**Q: Graph model phức tạp hơn, có đáng dùng không?**
> A: §3.2.3 nêu rõ: Graph linh hoạt nhất (unlimited edges/nodes),
> FGAC tốt nhất, nhưng query phức tạp hơn và cần học Cypher/Gremlin.

