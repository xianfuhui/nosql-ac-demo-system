/**
 * 10 kịch bản demo chạy THẬT trên MongoDB, bám sát các mục trong bài báo
 * NIST IR 8504 - "Access Control on NoSQL Databases" (Vincent C. Hu, 2024).
 *
 * Mỗi kịch bản trả về:
 * {
 *   input: string,            // yêu cầu/điều kiện đầu vào
 *   steps: string[],          // các truy vấn/thao tác thực thi thật trên DB
 *   expected: string,         // kết quả mong đợi theo bài báo
 *   pass: boolean,
 *   blocks: [{type, title, data}]  // DỮ LIỆU THẬT lấy trực tiếp từ MongoDB,
 *                                   // render bởi views/demo/_blocks.ejs
 * }
 */
const User = require("../models/User");
const MonHoc = require("../models/MonHoc");
const LopHoc = require("../models/LopHoc");
const Diem = require("../models/Diem");
const TaiLieu = require("../models/TaiLieu");
const Policy = require("../models/Policy");
const Log = require("../models/Log");
const GraphEdge = require("../models/GraphEdge");
const { checkAccess } = require("./accessControl");
const { mongoSanitize } = require("./_sanitizeStandalone");
const { traversePermission, neighborhood } = require("./graphTraversal");

async function getDemoUsers() {
  const [admin1, gvToan, gvVan, svAn, svBinh, svChau] = await Promise.all([
    User.findOne({ username: "admin1" }),
    User.findOne({ username: "gv_toan" }),
    User.findOne({ username: "gv_van" }),
    User.findOne({ username: "sv_an" }),
    User.findOne({ username: "sv_binh" }),
    User.findOne({ username: "sv_chau" }),
  ]);
  if (!admin1 || !gvToan || !gvVan || !svAn || !svBinh || !svChau) {
    throw new Error('Thiếu tài khoản demo. Vui lòng chạy "npm run seed" trước.');
  }
  return { admin1, gvToan, gvVan, svAn, svBinh, svChau };
}

async function logDemo(scenarioId, user, hanhDong, ketQua, chiTiet, doiTuong) {
  return Log.create({
    nguoiDungId: user ? user._id : null,
    tenDangNhap: user ? user.username : "demo-engine",
    vaiTro: user ? user.role : null,
    hanhDong,
    doiTuong: doiTuong || "",
    ketQua,
    chiTiet,
    kichBanDemo: scenarioId,
  });
}

function pickFields(doc, fields) {
  const out = {};
  fields.forEach((f) => (out[f] = doc ? doc[f] : undefined));
  return out;
}

// ===== 1. Truy cập hợp lệ — §3.2.2 Access Control Rules (Document Model) =====
async function scenario1() {
  const { svAn } = await getDemoUsers();
  const diem = await Diem.findOne({ sinhVienId: svAn._id }).lean();

  const decision = await checkAccess(svAn, "read", { resourceType: "diem", ownerId: svAn._id });
  await logDemo("scenario1", svAn, "read:diem", decision.allowed ? "allow" : "deny", decision.reason, "Điểm của chính sv_an");

  const matchedPolicy = decision.matchedPolicy ? decision.matchedPolicy.toObject() : null;

  return {
    input: `Subject: user "sv_an" (role=sinhvien). Action: read. Object: bản ghi điểm có ownerId = sv_an._id.`,
    steps: [
      `checkAccess(sv_an, 'read', {resourceType:'diem', ownerId: sv_an._id})`,
      `→ truy vấn Policy.find({active:true, action:'read', 'objectAttr.resourceType':'diem'}) rồi so khớp subject/object attribute.`,
    ],
    expected: "Khớp attribute chủ thể = attribute đối tượng (chính chủ) → allow, trả về đúng document điểm thật.",
    pass: decision.allowed === true,
    blocks: [
      { type: "record", title: "Policy thật đã khớp (collection: policies)", data: matchedPolicy ? pickFields(matchedPolicy, ["ten", "subjectAttr", "action", "objectAttr", "effect", "priority"]) : { ketQua: "Không khớp policy nào" } },
      { type: "record", title: "Document điểm thật được trả về (collection: diems)", data: diem ? pickFields(diem, ["_id", "sinhVienId", "diemChuyenCan", "diemGiuaKy", "diemCuoiKy", "diemTongKet"]) : null },
    ],
  };
}

// ===== 2. Truy cập trái phép — §4.2 Security (backdoor access to other users' data) =====
async function scenario2() {
  const { svAn, svBinh } = await getDemoUsers();
  const diemBinh = await Diem.findOne({ sinhVienId: svBinh._id }).lean();

  const decision = await checkAccess(svAn, "read", { resourceType: "diem", ownerId: svBinh._id });
  await logDemo("scenario2", svAn, "read:diem", decision.allowed ? "allow" : "deny", decision.reason, "Điểm của sv_binh (không phải chủ sở hữu)");

  return {
    input: `sv_an sửa URL để gọi: GET /grades/history/${diemBinh ? diemBinh._id : "..."} (bản ghi điểm KHÔNG thuộc về sv_an).`,
    steps: [
      `checkAccess(sv_an, 'read', {resourceType:'diem', ownerId: sv_binh._id})`,
      `Không có policy nào có scope='own' khớp (ownerId ≠ sv_an._id) và không có policy scope='any'/'assigned' cho role=sinhvien → mặc định DENY.`,
      `Request bị middleware requirePolicy chặn TRƯỚC khi route handler đọc dữ liệu — document gốc không bao giờ được truy vấn ra khỏi tầng ứng dụng.`,
    ],
    expected: "Theo §4.2: hệ thống phải tự ngăn 'backdoor access to other users' data' — từ chối (deny) và ghi log, không rò rỉ dữ liệu.",
    pass: decision.allowed === false,
    blocks: [
      { type: "code", title: "Quyết định thật từ policy engine (không phải diễn giải)", data: { allowed: decision.allowed, reason: decision.reason } },
      { type: "record", title: "Document điểm của sv_binh tồn tại thật trong DB (để đối chứng)", data: diemBinh ? pickFields(diemBinh, ["_id", "sinhVienId", "diemTongKet"]) : null },
      { type: "code", title: "Dữ liệu trả về cho sv_an qua route /grades/history/:id", data: "HTTP 403 — route trả error-403.ejs, KHÔNG include bất kỳ trường nào của document trên." },
    ],
  };
}

// ===== 3. Phân quyền chi tiết (FGAC) — §4.1 Fine-Grained Access Control =====
async function scenario3() {
  const { gvToan, gvVan } = await getDemoUsers();
  const lopToan = await LopHoc.findOne({ maLop: "GT1-N1" });

  // Cùng MỘT truy vấn logic (lấy điểm của lớp "GT1-N1"), nhưng truy vấn thật
  // luôn được ràng buộc thêm "lopHocId phải nằm trong danh sách lớp được phân công"
  // (dùng $and để tránh trùng khóa lopHocId trong cùng 1 object điều kiện).
  const queryFor = async (gv) => {
    const myClasses = await LopHoc.find({ giangVienId: gv._id }).select("_id").lean();
    const myClassIds = myClasses.map((c) => c._id);
    return Diem.find({ $and: [{ lopHocId: lopToan._id }, { lopHocId: { $in: myClassIds } }] })
      .select("sinhVienId diemTongKet lopHocId")
      .lean();
  };

  const resultToan = await queryFor(gvToan);
  const resultVan = await queryFor(gvVan);

  await logDemo("scenario3", gvToan, "read:diem", resultToan.length ? "allow" : "deny", `Truy vấn trả về ${resultToan.length} bản ghi`, lopToan.tenLop);
  await logDemo("scenario3", gvVan, "read:diem", resultVan.length ? "allow" : "deny", `Truy vấn trả về ${resultVan.length} bản ghi`, lopToan.tenLop);

  const pass = resultToan.length > 0 && resultVan.length === 0;

  return {
    input: `Cả 2 giảng viên cùng chạy một truy vấn logic: "lấy điểm của lớp ${lopToan.tenLop}" — nhưng truy vấn được RÀNG BUỘC thêm điều kiện lopHocId nằm trong danh sách lớp họ phụ trách.`,
    steps: [
      `Diem.find({$and: [{lopHocId:'${lopToan._id}'}, {lopHocId:{$in: lớp_của_gv_toan}}]})`,
      `Diem.find({$and: [{lopHocId:'${lopToan._id}'}, {lopHocId:{$in: lớp_của_gv_van}}]})`,
    ],
    expected: "§4.1: NoSQL thường chỉ cấp quyền toàn database hoặc không gì cả ('whole database or none'). Hệ thống này mô phỏng FGAC bằng cách ràng buộc điều kiện truy vấn theo phạm vi được phân công — gv_toan nhận dữ liệu thật, gv_van nhận tập rỗng dù gọi cùng 1 API.",
    pass,
    blocks: [
      { type: "table", title: `Kết quả THẬT khi gv_toan truy vấn (${resultToan.length} bản ghi)`, data: resultToan.map((d) => ({ sinhVienId: String(d.sinhVienId), diemTongKet: d.diemTongKet })) },
      { type: "table", title: `Kết quả THẬT khi gv_van truy vấn CÙNG lớp (${resultVan.length} bản ghi)`, data: resultVan.map((d) => ({ sinhVienId: String(d.sinhVienId), diemTongKet: d.diemTongKet })) },
    ],
  };
}

// ===== 4. Kiểm soát quyền sửa điểm — §3.2.2 + §4.1 áp dụng cho hành động "update" =====
async function scenario4() {
  const { gvToan, gvVan } = await getDemoUsers();
  const lopToan = await LopHoc.findOne({ maLop: "GT1-N1" });
  const diem = await Diem.findOne({ lopHocId: lopToan._id });
  const before = diem.toObject();

  // (a) gv_van KHÔNG được phân công lớp này -> thử ghi, phải bị chặn TRƯỚC khi update chạy.
  const decisionDeny = await checkAccess(gvVan, "update", { resourceType: "diem", assignedTo: [lopToan.giangVienId] });
  await logDemo("scenario4", gvVan, "update:diem", decisionDeny.allowed ? "allow" : "deny", decisionDeny.reason, lopToan.tenLop);

  // (b) gv_toan được phân công -> thực hiện UPDATE THẬT rồi đọc lại để chứng minh đã ghi.
  const decisionAllow = await checkAccess(gvToan, "update", { resourceType: "diem", assignedTo: [lopToan.giangVienId] });
  let afterToan = before;
  if (decisionAllow.allowed) {
    const newVal = before.diemCuoiKy === 9 ? 8.5 : 9;
    await Diem.updateOne({ _id: diem._id }, { $set: { diemCuoiKy: newVal, capNhatBoi: gvToan._id } });
    afterToan = (await Diem.findById(diem._id)).toObject();
    // khôi phục lại giá trị ban đầu để demo chạy lại nhiều lần vẫn nhất quán
    await Diem.updateOne({ _id: diem._id }, { $set: { diemCuoiKy: before.diemCuoiKy } });
  }
  await logDemo("scenario4", gvToan, "update:diem", decisionAllow.allowed ? "allow" : "deny", decisionAllow.reason, lopToan.tenLop);

  // Xác nhận document KHÔNG đổi sau nỗ lực của gv_van (đọc lại thật từ DB)
  const unchanged = await Diem.findById(diem._id).lean();

  const pass = decisionDeny.allowed === false && decisionAllow.allowed === true && String(unchanged.diemCuoiKy) === String(before.diemCuoiKy);

  return {
    input: `Lớp "${lopToan.tenLop}" do gv_toan phụ trách (object attribute "managed_by"=gv_toan). gv_van thử UPDATE; gv_toan thử UPDATE.`,
    steps: [
      `checkAccess(gv_van,'update',{assignedTo:[gv_toan._id]}) → nếu allow mới chạy Diem.updateOne(...).`,
      `checkAccess(gv_toan,'update',{assignedTo:[gv_toan._id]}) → allow → Diem.updateOne({diemCuoiKy: ...}) thực thi thật, rồi đọc lại bằng Diem.findById để xác nhận đã ghi, sau đó phục hồi giá trị gốc.`,
      `Diem.findById(diem._id) lần cuối để xác nhận document KHÔNG bị gv_van thay đổi.`,
    ],
    expected: "gv_van: deny, KHÔNG có lệnh update nào được gọi · gv_toan: allow, document thay đổi thật rồi được phục hồi.",
    pass,
    blocks: [
      { type: "code", title: "Quyết định cho gv_van", data: { allowed: decisionDeny.allowed, reason: decisionDeny.reason, update_executed: false } },
      { type: "diff", title: "Document điểm THẬT trước/sau khi gv_toan cập nhật (đã phục hồi sau demo)", data: { before: pickFields(before, ["diemChuyenCan", "diemGiuaKy", "diemCuoiKy", "diemTongKet"]), after: pickFields(afterToan, ["diemChuyenCan", "diemGiuaKy", "diemCuoiKy", "diemTongKet"]) } },
    ],
  };
}

// ===== 5. Kiểm tra NoSQL Injection — §4.2 Security (toán tử $where, injection attacks) =====
async function scenario5() {
  // Payload mô phỏng kiểu tấn công dùng toán tử Mongo ($ne) để vượt điều kiện so khớp,
  // đúng như bài báo mô tả: "an attacker can exploit... passing arbitrary operators
  // into the query" (ví dụ điển hình: toán tử $where / $ne).
  const maliciousPayload = { username: { $ne: null }, password: { $ne: null } };

  const vulnerableDocs = await User.find({ username: maliciousPayload.username }).select("username role").lean();

  const blocked = [];
  const sanitized = mongoSanitize(maliciousPayload, blocked);
  const safeFilter = Object.keys(sanitized.username || {}).length === 0 ? { _id: null } : { username: sanitized.username };
  const safeDocs = await User.find(safeFilter).select("username role").lean();

  await logDemo("scenario5", null, "nosql_injection_test", "info", `Toán tử bị chặn: [${blocked.join(", ")}]`);

  const pass = blocked.length > 0 && safeDocs.length === 0 && vulnerableDocs.length > 0;

  return {
    input: `Payload gửi lên server: ${JSON.stringify(maliciousPayload)} — dùng toán tử "$ne" giống cách bài báo mô tả tấn công injection qua toán tử Mongo (vd "$where").`,
    steps: [
      `KHÔNG sanitize: User.find({username: {$ne:null}}) chạy trực tiếp với toán tử injection.`,
      `CÓ sanitize (middleware/sanitize.js đang bật cho mọi request thật): loại bỏ mọi khóa bắt đầu bằng "$" trước khi query chạy.`,
      `User.find(filter đã sanitize) chạy lại với điều kiện an toàn.`,
    ],
    expected: "Nếu không phòng thủ: injection khớp MỌI user (rò rỉ toàn bộ danh sách). Có middleware: toán tử bị loại, truy vấn không trả dữ liệu nhạy cảm nào.",
    pass,
    blocks: [
      { type: "code", title: "Payload độc hại gửi lên (thật)", data: maliciousPayload },
      { type: "table", title: `KHÔNG sanitize — ${vulnerableDocs.length} user bị lộ (minh họa lỗ hổng nếu tắt middleware)`, data: vulnerableDocs.map((u) => ({ username: u.username, role: u.role })) },
      { type: "code", title: "Sau khi middleware mongoSanitize xử lý (dữ liệu thật)", data: { khoaBiChan: blocked, filterAnToan: sanitized } },
      { type: "table", title: `CÓ sanitize (middleware đang bật thật trong app.js) — ${safeDocs.length} user bị lộ`, data: safeDocs.map((u) => ({ username: u.username, role: u.role })) },
    ],
  };
}

// ===== 6. Kiểm tra nhật ký — §4.6 Audit =====
async function scenario6() {
  const recentCount = await Log.countDocuments();
  const recentLogs = await Log.find().sort({ thoiGian: -1 }).limit(10).lean();

  const pass = recentCount > 0;
  return {
    input: `Truy vấn trực tiếp collection "logs" — nơi mọi hành động quan trọng (đăng nhập, allow/deny truy cập, sửa điểm...) được ghi lại thật.`,
    steps: [`Log.countDocuments()`, `Log.find().sort({thoiGian:-1}).limit(10)`],
    expected: "§4.6: hệ thống NoSQL thường thiếu công cụ audit sẵn có — ứng dụng phải tự ghi log ở tầng middleware cho mọi request allow/deny.",
    pass,
    blocks: [
      {
        type: "table",
        title: `${recentCount} bản ghi log thật trong hệ thống — 10 bản ghi gần nhất`,
        data: recentLogs.map((l) => ({
          thoiGian: l.thoiGian,
          nguoiDung: l.tenDangNhap,
          hanhDong: l.hanhDong,
          ketQua: l.ketQua,
          chiTiet: l.chiTiet,
        })),
      },
    ],
  };
}

// ===== 8. Thay đổi chính sách & tính nhất quán — §4.4 Data Consistency =====
async function scenario8() {
  const { gvToan } = await getDemoUsers();
  const lopToan = await LopHoc.findOne({ maLop: "GT1-N1" });
  const policy = await Policy.findOne({ ten: "Giảng viên sửa điểm lớp phụ trách" });
  if (!policy) throw new Error("Không tìm thấy policy demo. Hãy chạy lại seed dữ liệu.");

  const before = await checkAccess(gvToan, "update", { resourceType: "diem", assignedTo: [lopToan.giangVienId] });
  const policyBefore = (await Policy.findById(policy._id)).toObject();

  policy.active = false;
  await policy.save();
  const afterDisable = await checkAccess(gvToan, "update", { resourceType: "diem", assignedTo: [lopToan.giangVienId] });
  const policyDisabled = (await Policy.findById(policy._id)).toObject();

  policy.active = true;
  await policy.save();
  const afterEnable = await checkAccess(gvToan, "update", { resourceType: "diem", assignedTo: [lopToan.giangVienId] });
  const policyRestored = (await Policy.findById(policy._id)).toObject();

  await logDemo("scenario8", gvToan, "policy_consistency_test", "info", `before=${before.allowed}, afterDisable=${afterDisable.allowed}, afterEnable=${afterEnable.allowed}`);

  const pass = before.allowed === true && afterDisable.allowed === false && afterEnable.allowed === true;

  return {
    input: `Document policy "${policy.ten}" (collection: policies, _id=${policy._id}) quyết định quyền sửa điểm của giảng viên phụ trách.`,
    steps: [
      `Đọc policy.active lần 1 → gọi checkAccess() ngay sau đó.`,
      `Admin set policy.active=false, lưu, rồi ĐỌC LẠI NGAY (cùng tiến trình, cùng node Mongo) → gọi checkAccess() lần 2.`,
      `Khôi phục policy.active=true, lưu, đọc lại → gọi checkAccess() lần 3.`,
    ],
    expected: "§4.4: trên 1 node MongoDB đơn (demo này), thay đổi có hiệu lực ngay cho lần đọc kế tiếp. Bài báo lưu ý: trên cụm NoSQL phân tán nhiều node, dữ liệu có thể CHƯA đồng bộ ngay giữa các node (eventual consistency) — đây là đánh đổi consistency vs performance mà ứng dụng phải tự xử lý.",
    pass,
    blocks: [
      { type: "diff", title: "Document policy thật — bước 1 → bước 2 (tắt)", data: { before: pickFields(policyBefore, ["active"]), after: pickFields(policyDisabled, ["active"]) } },
      { type: "diff", title: "Document policy thật — bước 2 → bước 3 (bật lại)", data: { before: pickFields(policyDisabled, ["active"]), after: pickFields(policyRestored, ["active"]) } },
      {
        type: "table",
        title: "Quyết định checkAccess() thật tương ứng từng bước",
        data: [
          { buoc: "1. Ban đầu (active=true)", ketQua: before.allowed ? "allow" : "deny" },
          { buoc: "2. Sau khi tắt (active=false)", ketQua: afterDisable.allowed ? "allow" : "deny" },
          { buoc: "3. Sau khi bật lại (active=true)", ketQua: afterEnable.allowed ? "allow" : "deny" },
        ],
      },
    ],
  };
}

// ===== 9. Minh họa mô hình dữ liệu NoSQL — §2 + §3.1 (Document Model, Fig. 3 & Fig. 5) =====
async function scenario9() {
  const diem = await Diem.findOne().lean();
  const user = await User.findById(diem.sinhVienId).lean();

  // Cây phân cấp 5 mức theo Fig. 5: Database -> Collection -> Document -> Field -> (giá trị lồng)
  const tree = {
    levelLabel: "Mức 1: Database",
    label: "edu_nosql_ac",
    children: [
      {
        levelLabel: "Mức 2: Collection",
        label: "diems",
        children: [
          {
            levelLabel: "Mức 3: Document (khóa bởi _id)",
            label: String(diem._id),
            children: Object.keys(diem)
              .filter((k) => k !== "_id" && k !== "__v")
              .map((k) => ({
                levelLabel: "Mức 4: Field",
                label: k,
                value: diem[k] && typeof diem[k] === "object" && !(diem[k] instanceof Date) ? undefined : diem[k],
                children:
                  diem[k] && typeof diem[k] === "object" && !(diem[k] instanceof Date)
                    ? [{ levelLabel: "Mức 5: Giá trị lồng", label: "(ObjectId/subdocument)", value: String(diem[k]) }]
                    : [],
              })),
          },
        ],
      },
    ],
  };

  return {
    input: `Lấy 1 document thật từ collection "diems" (mô hình Document, §2.1.3, Fig. 3) và biểu diễn theo cấu trúc cây 5 mức của §3.1 (Fig. 5).`,
    steps: [`Diem.findOne().lean()`, `Dựng cây: Database → Collection → Document → Field → giá trị lồng`],
    expected: "MongoDB dùng mô hình Document: mỗi document là JSON/BSON lồng nhau, không cần JOIN để đọc dữ liệu liên quan trong cùng document — khác RDBMS dùng bảng phẳng.",
    pass: !!diem,
    blocks: [{ type: "tree", title: "Cây phân cấp dữ liệu THẬT (đúng Fig. 5 của bài báo)", data: tree }],
  };
}

// ===== 10. Phân quyền trên dữ liệu dạng đồ thị — §3.2.3 Graph Model (Fig. 9 & Fig. 10) =====
async function scenario10() {
  const { svAn, svBinh } = await getDemoUsers();

  // Trường hợp (a): sv_an đọc điểm CHÍNH MÌNH — phải tìm thấy cạnh "can_read" nhúng sẵn.
  const resultOwn = await traversePermission("user:sv_an", "can_read", "resource:diem_svAn");
  // Trường hợp (b): sv_an cố đọc điểm sv_binh — KHÔNG có cạnh nào như vậy trong đồ thị.
  const resultOther = await traversePermission("user:sv_an", "can_read", "resource:diem_svBinh");

  const nb = await neighborhood("user:sv_an");

  await logDemo("scenario10", svAn, "graph_traversal:own", resultOwn.found ? "allow" : "deny", `Tìm thấy ${resultOwn.path.length} cạnh`);
  await logDemo("scenario10", svAn, "graph_traversal:other", resultOther.found ? "allow" : "deny", `Tìm thấy ${resultOther.path.length} cạnh`);

  const pass = resultOwn.found === true && resultOther.found === false;

  return {
    input: `Collection "graphedges" lưu luật phân quyền NHÚNG TRỰC TIẾP làm cạnh đồ thị (đúng Fig. 10: "user x -in-> group y -can read-> file y"), không qua collection "policies" riêng như các kịch bản khác.`,
    steps: [
      `traversePermission('user:sv_an', 'can_read', 'resource:diem_svAn') → BFS thật trên GraphEdge.find(...)`,
      `traversePermission('user:sv_an', 'can_read', 'resource:diem_svBinh') → BFS thật trên cùng collection`,
    ],
    expected: "§3.2.3: 'the access control rule can be directly embedded in the database, treating a sequence of links as a rule'. sv_an có cạnh can_read trực tiếp tới điểm của chính mình (allow) nhưng KHÔNG có cạnh nào tới điểm sv_binh (deny) — vì đồ thị không lưu quan hệ đó.",
    pass,
    blocks: [
      { type: "graph", title: "Duyệt đồ thị THẬT: sv_an → điểm của chính mình", data: { found: resultOwn.found, path: resultOwn.path, fromKey: "user:sv_an", permissionType: "can_read", toKey: "resource:diem_svAn" } },
      { type: "graph", title: "Duyệt đồ thị THẬT: sv_an → điểm của sv_binh", data: { found: resultOther.found, path: resultOther.path, fromKey: "user:sv_an", permissionType: "can_read", toKey: "resource:diem_svBinh" } },
      {
        type: "table",
        title: "Toàn bộ cạnh THẬT xuất phát từ node user:sv_an (collection graphedges)",
        data: nb.outgoing.map((e) => ({ from: e.from, type: e.type, to: e.to })),
      },
    ],
  };
}

const SCENARIOS = [
  { id: "scenario1", title: "1. Truy cập hợp lệ", baibaoRef: "§3.2.2 Access Control Rules (Document Model)", run: scenario1 },
  { id: "scenario2", title: "2. Truy cập trái phép", baibaoRef: "§4.2 Security — backdoor access to other users' data", run: scenario2 },
  { id: "scenario3", title: "3. Phân quyền chi tiết (FGAC)", baibaoRef: "§4.1 Fine-Grained Access Control", run: scenario3 },
  { id: "scenario4", title: "4. Kiểm soát quyền sửa điểm", baibaoRef: "§3.2.2 · §4.1 áp dụng cho hành động update", run: scenario4 },
  { id: "scenario5", title: "5. Kiểm tra NoSQL Injection", baibaoRef: "§4.2 Security — injection attacks ($where/$ne)", run: scenario5 },
  { id: "scenario6", title: "6. Kiểm tra nhật ký", baibaoRef: "§4.6 Audit", run: scenario6 },
  { id: "scenario7", title: "7. AI hỗ trợ tạo quy tắc", baibaoRef: "§4.8 Support for AI", link: "/ai" },
  { id: "scenario8", title: "8. Thay đổi chính sách & tính nhất quán", baibaoRef: "§4.4 Data Consistency", run: scenario8 },
  { id: "scenario9", title: "9. Minh họa mô hình dữ liệu NoSQL", baibaoRef: "§2 Overview · §3.1 Relationship Structures (Fig. 3, Fig. 5)", run: scenario9 },
  { id: "scenario10", title: "10. Phân quyền trên dữ liệu dạng đồ thị", baibaoRef: "§3.2.3 Graph Model (Fig. 9, Fig. 10)", run: scenario10 },
];

module.exports = { SCENARIOS, getDemoUsers };
