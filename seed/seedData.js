const bcrypt = require("bcryptjs");

const User = require("../models/User");
const MonHoc = require("../models/MonHoc");
const LopHoc = require("../models/LopHoc");
const Diem = require("../models/Diem");
const LichSuDiem = require("../models/LichSuDiem");
const TaiLieu = require("../models/TaiLieu");
const Log = require("../models/Log");
const Policy = require("../models/Policy");
const GraphNode = require("../models/GraphNode");
const GraphEdge = require("../models/GraphEdge");

/**
 * Hàm seed dữ liệu mẫu — không tự kết nối/đóng DB, để có thể gọi lại được
 * cả từ CLI (seed/run.js) lẫn tự động lúc khởi động app.js khi dùng
 * MongoDB in-memory (vì CSDL in-memory chỉ tồn tại trong vòng đời 1 process).
 */
async function seedData() {
  console.log("Đang xóa dữ liệu cũ (nếu có)...");
  await Promise.all([
    User.deleteMany({}),
    MonHoc.deleteMany({}),
    LopHoc.deleteMany({}),
    Diem.deleteMany({}),
    LichSuDiem.deleteMany({}),
    TaiLieu.deleteMany({}),
    Log.deleteMany({}),
    Policy.deleteMany({}),
    GraphNode.deleteMany({}),
    GraphEdge.deleteMany({}),
  ]);

  const hash = await bcrypt.hash("123456", 10);

  console.log("Tạo tài khoản...");
  const admin1 = await User.create({ username: "admin1", passwordHash: hash, hoTen: "Nguyễn Văn Admin", email: "admin1@truong.edu.vn", role: "admin" });
  const gvToan = await User.create({ username: "gv_toan", passwordHash: hash, hoTen: "Trần Thị Toán", email: "gv.toan@truong.edu.vn", role: "giangvien", khoa: "Toán - Tin" });
  const gvVan = await User.create({ username: "gv_van", passwordHash: hash, hoTen: "Lê Văn Vinh", email: "gv.van@truong.edu.vn", role: "giangvien", khoa: "Ngữ Văn" });
  const svAn = await User.create({ username: "sv_an", passwordHash: hash, hoTen: "Phạm Văn An", email: "sv.an@truong.edu.vn", role: "sinhvien", khoa: "CNTT" });
  const svBinh = await User.create({ username: "sv_binh", passwordHash: hash, hoTen: "Nguyễn Thị Bình", email: "sv.binh@truong.edu.vn", role: "sinhvien", khoa: "CNTT" });
  const svChau = await User.create({ username: "sv_chau", passwordHash: hash, hoTen: "Lý Thị Châu", email: "sv.chau@truong.edu.vn", role: "sinhvien", khoa: "Ngữ Văn" });

  console.log("Tạo môn học...");
  const monToan = await MonHoc.create({ maMon: "MATH101", tenMon: "Giải tích 1", khoa: "Toán - Tin", soTinChi: 4, giangVienIds: [gvToan._id] });
  const monVan = await MonHoc.create({ maMon: "VAN101", tenMon: "Văn học Việt Nam", khoa: "Ngữ Văn", soTinChi: 3, giangVienIds: [gvVan._id] });

  console.log("Tạo lớp học...");
  const lopToan = await LopHoc.create({
    maLop: "GT1-N1", tenLop: "Giải tích 1 - Nhóm 1", monHocId: monToan._id, giangVienId: gvToan._id,
    khoa: "Toán - Tin", siSoToiDa: 40, sinhVienIds: [svAn._id, svBinh._id],
  });
  const lopVan = await LopHoc.create({
    maLop: "VH1-N1", tenLop: "Văn học VN - Nhóm 1", monHocId: monVan._id, giangVienId: gvVan._id,
    khoa: "Ngữ Văn", siSoToiDa: 40, sinhVienIds: [svChau._id],
  });

  await User.findByIdAndUpdate(gvToan._id, { lopPhuTrach: [lopToan._id], monPhuTrach: [monToan._id] });
  await User.findByIdAndUpdate(gvVan._id, { lopPhuTrach: [lopVan._id], monPhuTrach: [monVan._id] });
  await User.findByIdAndUpdate(svAn._id, { lopId: lopToan._id });
  await User.findByIdAndUpdate(svBinh._id, { lopId: lopToan._id });
  await User.findByIdAndUpdate(svChau._id, { lopId: lopVan._id });

  console.log("Tạo điểm...");
  const diemAn = await Diem.create({ sinhVienId: svAn._id, lopHocId: lopToan._id, monHocId: monToan._id, diemChuyenCan: 8, diemGiuaKy: 7.5, diemCuoiKy: 8, diemTongKet: 7.8, capNhatBoi: gvToan._id });
  const diemBinh = await Diem.create({ sinhVienId: svBinh._id, lopHocId: lopToan._id, monHocId: monToan._id, diemChuyenCan: 9, diemGiuaKy: 8, diemCuoiKy: 8.5, diemTongKet: 8.3, capNhatBoi: gvToan._id });
  const diemChau = await Diem.create({ sinhVienId: svChau._id, lopHocId: lopVan._id, monHocId: monVan._id, diemChuyenCan: 7, diemGiuaKy: 6.5, diemCuoiKy: 7, diemTongKet: 6.8, capNhatBoi: gvVan._id });

  await LichSuDiem.create({
    diemId: diemAn._id, sinhVienId: svAn._id, lopHocId: lopToan._id, truong: "diemGiuaKy",
    giaTriCu: null, giaTriMoi: 7.5, nguoiSua: gvToan._id,
  });

  console.log("Tạo tài liệu...");
  await TaiLieu.create({
    tenTaiLieu: "Đề cương Giải tích 1", moTa: "Nội dung ôn tập chương 1-3",
    monHocId: monToan._id, lopHocId: lopToan._id,
    noiDung: "Chương 1: Giới hạn dãy số. Chương 2: Đạo hàm. Chương 3: Tích phân.",
    nguoiTaiLen: gvToan._id,
  });
  await TaiLieu.create({
    tenTaiLieu: "Tài liệu Văn học Việt Nam hiện đại", moTa: "Tổng hợp tác phẩm trọng tâm",
    monHocId: monVan._id, lopHocId: lopVan._id,
    noiDung: "Phân tích các tác phẩm: Số đỏ, Chí Phèo, Vợ nhặt...",
    nguoiTaiLen: gvVan._id,
  });

  console.log("Tạo chính sách phân quyền (ABAC) mặc định...");
  await Policy.create([
    {
      ten: "Admin toàn quyền xem điểm",
      moTa: "Quản trị viên có quyền xem mọi bản ghi điểm trong hệ thống.",
      subjectAttr: { role: "admin", khoa: null, scope: "any" },
      action: "read", objectAttr: { resourceType: "diem", khoa: null },
      effect: "allow", priority: 1,
    },
    {
      ten: "Admin toàn quyền sửa điểm",
      moTa: "Quản trị viên có quyền nhập/sửa mọi bản ghi điểm.",
      subjectAttr: { role: "admin", khoa: null, scope: "any" },
      action: "update", objectAttr: { resourceType: "diem", khoa: null },
      effect: "allow", priority: 1,
    },
    {
      ten: "Giảng viên xem điểm lớp phụ trách",
      moTa: "Giảng viên chỉ được xem điểm các lớp mình được phân công giảng dạy (fine-grained).",
      subjectAttr: { role: "giangvien", khoa: null, scope: "assigned" },
      action: "read", objectAttr: { resourceType: "diem", khoa: null },
      effect: "allow", priority: 5,
    },
    {
      ten: "Giảng viên sửa điểm lớp phụ trách",
      moTa: "Giảng viên chỉ được nhập/sửa điểm các lớp mình được phân công giảng dạy — không được sửa điểm lớp khác.",
      subjectAttr: { role: "giangvien", khoa: null, scope: "assigned" },
      action: "update", objectAttr: { resourceType: "diem", khoa: null },
      effect: "allow", priority: 5,
    },
    {
      ten: "Sinh viên xem điểm của chính mình",
      moTa: "Sinh viên chỉ được xem điểm của bản thân, không xem được điểm của sinh viên khác (ownership-based).",
      subjectAttr: { role: "sinhvien", khoa: null, scope: "own" },
      action: "read", objectAttr: { resourceType: "diem", khoa: null },
      effect: "allow", priority: 5,
    },
  ]);

  console.log("Tạo đồ thị thật (Graph Model, §3.2.3 — Fig. 9 & Fig. 10 của bài báo)...");
  // Node: user, group (lớp), course (môn), resource (bản ghi điểm) — dữ liệu
  // THẬT, trỏ refId sang đúng document gốc trong các collection khác.
  const nodes = [
    { key: "user:sv_an", kind: "user", label: "sv_an (Phạm Văn An)", refId: svAn._id },
    { key: "user:sv_binh", kind: "user", label: "sv_binh (Nguyễn Thị Bình)", refId: svBinh._id },
    { key: "user:sv_chau", kind: "user", label: "sv_chau (Lý Thị Châu)", refId: svChau._id },
    { key: "user:gv_toan", kind: "user", label: "gv_toan (Trần Thị Toán)", refId: gvToan._id },
    { key: "user:gv_van", kind: "user", label: "gv_van (Lê Văn Vinh)", refId: gvVan._id },
    { key: "group:GT1-N1", kind: "group", label: "Lớp GT1-N1 (Giải tích 1)", refId: lopToan._id },
    { key: "group:VH1-N1", kind: "group", label: "Lớp VH1-N1 (Văn học VN)", refId: lopVan._id },
    { key: "course:MATH101", kind: "course", label: "Môn MATH101 (Giải tích 1)", refId: monToan._id },
    { key: "course:VAN101", kind: "course", label: "Môn VAN101 (Văn học VN)", refId: monVan._id },
    { key: "resource:diem_svAn", kind: "resource", label: "Bản ghi điểm của sv_an", refId: diemAn._id },
    { key: "resource:diem_svBinh", kind: "resource", label: "Bản ghi điểm của sv_binh", refId: diemBinh._id },
    { key: "resource:diem_svChau", kind: "resource", label: "Bản ghi điểm của sv_chau", refId: diemChau._id },
  ];
  await GraphNode.create(nodes);

  const edges = [
    // Chuỗi thuộc tính SUBJECT — đúng mẫu Fig. 9:
    // "user x (node) in (edge) group y (node) works for (edge) company z (node)"
    { from: "user:sv_an", type: "in", to: "group:GT1-N1" },
    { from: "user:sv_binh", type: "in", to: "group:GT1-N1" },
    { from: "user:sv_chau", type: "in", to: "group:VH1-N1" },
    { from: "group:GT1-N1", type: "thuoc_mon", to: "course:MATH101" },
    { from: "group:VH1-N1", type: "thuoc_mon", to: "course:VAN101" },
    { from: "group:GT1-N1", type: "managed_by", to: "user:gv_toan" },
    { from: "group:VH1-N1", type: "managed_by", to: "user:gv_van" },

    // Chuỗi thuộc tính OBJECT — đúng mẫu Fig. 9:
    // "file f (node) managed by (edge) department d (node) belongs to (edge) organization o (node)"
    { from: "resource:diem_svAn", type: "owned_by", to: "user:sv_an" },
    { from: "resource:diem_svAn", type: "managed_by", to: "user:gv_toan" },
    { from: "resource:diem_svAn", type: "belongs_to", to: "course:MATH101" },
    { from: "resource:diem_svBinh", type: "owned_by", to: "user:sv_binh" },
    { from: "resource:diem_svBinh", type: "managed_by", to: "user:gv_toan" },
    { from: "resource:diem_svBinh", type: "belongs_to", to: "course:MATH101" },
    { from: "resource:diem_svChau", type: "owned_by", to: "user:sv_chau" },
    { from: "resource:diem_svChau", type: "managed_by", to: "user:gv_van" },
    { from: "resource:diem_svChau", type: "belongs_to", to: "course:VAN101" },

    // Cạnh HÀNH ĐỘNG ĐƯỢC PHÉP — đúng mẫu Fig. 10: "user x -in-> group y -can
    // read-> file y". Luật phân quyền được nhúng THẲNG vào đồ thị dưới dạng
    // cạnh "can_read" xuất phát từ node user, KHÔNG tra cứu qua policy riêng.
    { from: "user:sv_an", type: "can_read", to: "resource:diem_svAn" },
    { from: "user:sv_binh", type: "can_read", to: "resource:diem_svBinh" },
    { from: "user:sv_chau", type: "can_read", to: "resource:diem_svChau" },
    { from: "user:gv_toan", type: "can_read", to: "resource:diem_svAn" },
    { from: "user:gv_toan", type: "can_read", to: "resource:diem_svBinh" },
    { from: "user:gv_van", type: "can_read", to: "resource:diem_svChau" },
  ];
  await GraphEdge.create(edges);

  console.log("Ghi vài log mẫu...");
  await Log.create([
    { tenDangNhap: "admin1", vaiTro: "admin", hanhDong: "seed", ketQua: "info", chiTiet: "Khởi tạo dữ liệu mẫu ban đầu" },
  ]);

  console.log("\n✅ Seed dữ liệu thành công!");
  console.log("Tài khoản demo (mật khẩu đều là 123456):");
  console.log("  - admin1   (Quản trị viên)");
  console.log("  - gv_toan  (Giảng viên - phụ trách lớp Giải tích 1)");
  console.log("  - gv_van   (Giảng viên - phụ trách lớp Văn học VN)");
  console.log("  - sv_an    (Sinh viên - lớp Giải tích 1)");
  console.log("  - sv_binh  (Sinh viên - lớp Giải tích 1)");
  console.log("  - sv_chau  (Sinh viên - lớp Văn học VN)\n");
}

module.exports = { seedData };
