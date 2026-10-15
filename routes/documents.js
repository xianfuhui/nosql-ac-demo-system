const express = require("express");
const router = express.Router();
const { requireLogin } = require("../middleware/auth");
const { writeLog } = require("../utils/accessControl");
const TaiLieu = require("../models/TaiLieu");
const LopHoc = require("../models/LopHoc");
const MonHoc = require("../models/MonHoc");

router.use(requireLogin);

// Chức năng #10 Quản lý tài liệu + #11 Xem/tải tài liệu
router.get("/", async (req, res) => {
  const user = req.session.user;
  let docs;
  if (user.role === "admin") {
    docs = await TaiLieu.find().populate("monHocId", "tenMon").populate("lopHocId", "tenLop").populate("nguoiTaiLen", "hoTen");
  } else if (user.role === "giangvien") {
    const myClasses = await LopHoc.find({ giangVienId: user._id }).select("_id");
    docs = await TaiLieu.find({
      $or: [{ nguoiTaiLen: user._id }, { lopHocId: { $in: myClasses.map((c) => c._id) } }],
    })
      .populate("monHocId", "tenMon")
      .populate("lopHocId", "tenLop")
      .populate("nguoiTaiLen", "hoTen");
  } else {
    // Sinh viên chỉ thấy tài liệu của lớp mình đang học, kể cả tài liệu
    // đăng cho "mọi lớp" của môn học đó (lopHocId = null) — FGAC
    const myLop = user.lopId ? await LopHoc.findById(user.lopId) : null;
    const orConds = [{ lopHocId: user.lopId }];
    if (myLop) orConds.push({ lopHocId: null, monHocId: myLop.monHocId });
    docs = await TaiLieu.find({ $or: orConds })
      .populate("monHocId", "tenMon")
      .populate("lopHocId", "tenLop")
      .populate("nguoiTaiLen", "hoTen");
  }
  await writeLog(req, user, "read:tailieu", "allow", `Xem danh sách tài liệu (${docs.length} mục trong phạm vi quyền)`);
  res.render("documents/list", { title: "Tài liệu học tập", active: "documents", docs, user });
});

router.get("/new", async (req, res) => {
  const user = req.session.user;
  if (user.role === "sinhvien") {
    return res.status(403).render("error-403", { user, reason: "Sinh viên không có quyền đăng tài liệu." });
  }
  const monHocs = user.role === "admin" ? await MonHoc.find() : await MonHoc.find({ giangVienIds: user._id });
  const lopHocs = user.role === "admin" ? await LopHoc.find() : await LopHoc.find({ giangVienId: user._id });
  res.render("documents/form", { title: "Đăng tài liệu", active: "documents", monHocs, lopHocs, user });
});

router.post("/", async (req, res) => {
  const user = req.session.user;
  if (user.role === "sinhvien") {
    await writeLog(req, user, "create:tailieu", "deny", "Sinh viên không có quyền đăng tài liệu");
    return res.status(403).render("error-403", { user, reason: "Sinh viên không có quyền đăng tài liệu." });
  }
  const { tenTaiLieu, moTa, monHocId, lopHocId, noiDung } = req.body;
  const doc = await TaiLieu.create({ tenTaiLieu, moTa, monHocId, lopHocId: lopHocId || null, noiDung, nguoiTaiLen: user._id });
  await writeLog(req, user, "create:tailieu", "allow", `Đăng tài liệu "${tenTaiLieu}"`);
  res.redirect("/documents");
});

router.get("/:id", async (req, res) => {
  const user = req.session.user;
  const doc = await TaiLieu.findById(req.params.id).populate("monHocId").populate("lopHocId").populate("nguoiTaiLen", "hoTen");
  if (!doc) return res.status(404).render("error-404");

  let allowed =
    user.role === "admin" ||
    String(doc.nguoiTaiLen._id) === String(user._id) ||
    (user.role === "sinhvien" && doc.lopHocId && String(doc.lopHocId._id) === String(user.lopId)) ||
    (user.role === "giangvien" && doc.lopHocId && (await LopHoc.exists({ _id: doc.lopHocId._id, giangVienId: user._id })));

  // Tài liệu áp dụng cho "mọi lớp" của môn (lopHocId = null): kiểm tra theo môn học
  if (!allowed && !doc.lopHocId) {
    if (user.role === "sinhvien" && user.lopId) {
      const myLop = await LopHoc.findById(user.lopId);
      allowed = !!(myLop && String(myLop.monHocId) === String(doc.monHocId._id));
    } else if (user.role === "giangvien") {
      allowed = !!(await LopHoc.exists({ monHocId: doc.monHocId._id, giangVienId: user._id }));
    }
  }

  if (!allowed) {
    await writeLog(req, user, "read:tailieu", "deny", "Không thuộc lớp/môn của tài liệu này", doc.tenTaiLieu);
    return res.status(403).render("error-403", { user, reason: "Tài liệu này không thuộc lớp/môn bạn được phép truy cập." });
  }
  await writeLog(req, user, "read:tailieu", "allow", "Xem/tải tài liệu", doc.tenTaiLieu);
  res.render("documents/detail", { title: doc.tenTaiLieu, active: "documents", doc, user });
});

router.post("/:id/delete", async (req, res) => {
  const user = req.session.user;
  const doc = await TaiLieu.findById(req.params.id);
  if (!doc) return res.status(404).render("error-404");
  if (user.role !== "admin" && String(doc.nguoiTaiLen) !== String(user._id)) {
    await writeLog(req, user, "delete:tailieu", "deny", "Không phải người đăng tài liệu");
    return res.status(403).render("error-403", { user, reason: "Bạn không phải người đăng tài liệu này." });
  }
  await TaiLieu.findByIdAndDelete(req.params.id);
  await writeLog(req, user, "delete:tailieu", "allow", `Xóa tài liệu "${doc.tenTaiLieu}"`);
  res.redirect("/documents");
});

module.exports = router;
