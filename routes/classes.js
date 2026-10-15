const express = require("express");
const router = express.Router();
const { requireLogin, requireRole } = require("../middleware/auth");
const { writeLog } = require("../utils/accessControl");
const LopHoc = require("../models/LopHoc");
const MonHoc = require("../models/MonHoc");
const User = require("../models/User");

router.use(requireLogin);

// Chức năng #7 Quản lý lớp học
router.get("/", async (req, res) => {
  const user = req.session.user;
  let filter = {};
  if (user.role === "giangvien") filter = { giangVienId: user._id };
  if (user.role === "sinhvien") filter = { sinhVienIds: user._id };
  const classes = await LopHoc.find(filter)
    .populate("monHocId", "tenMon maMon")
    .populate("giangVienId", "hoTen");
  res.render("classes/list", { title: "Lớp học", active: "classes", classes, user });
});

router.get("/new", requireRole("admin"), async (req, res) => {
  const monHocs = await MonHoc.find();
  const giangViens = await User.find({ role: "giangvien" });
  res.render("classes/form", { title: "Thêm lớp học", active: "classes", lop: null, monHocs, giangViens, error: null });
});

router.post("/", requireRole("admin"), async (req, res) => {
  try {
    const { maLop, tenLop, monHocId, giangVienId, khoa, siSoToiDa } = req.body;
    const lop = await LopHoc.create({ maLop, tenLop, monHocId, giangVienId, khoa, siSoToiDa: Number(siSoToiDa) || 60 });
    await User.findByIdAndUpdate(giangVienId, { $addToSet: { lopPhuTrach: lop._id } });
    await writeLog(req, req.session.user, "create:lophoc", "allow", `Tạo lớp ${maLop} - ${tenLop}`);
    res.redirect("/classes");
  } catch (err) {
    const monHocs = await MonHoc.find();
    const giangViens = await User.find({ role: "giangvien" });
    res.render("classes/form", { title: "Thêm lớp học", active: "classes", lop: null, monHocs, giangViens, error: err.message });
  }
});

router.get("/:id/edit", requireRole("admin"), async (req, res) => {
  const lop = await LopHoc.findById(req.params.id);
  const monHocs = await MonHoc.find();
  const giangViens = await User.find({ role: "giangvien" });
  res.render("classes/form", { title: "Sửa lớp học", active: "classes", lop, monHocs, giangViens, error: null });
});

router.post("/:id", requireRole("admin"), async (req, res) => {
  const { tenLop, monHocId, giangVienId, khoa, siSoToiDa } = req.body;
  await LopHoc.findByIdAndUpdate(req.params.id, { tenLop, monHocId, giangVienId, khoa, siSoToiDa: Number(siSoToiDa) || 60 });
  await writeLog(req, req.session.user, "update:lophoc", "allow", `Cập nhật lớp ${req.params.id}`);
  res.redirect("/classes");
});

router.post("/:id/delete", requireRole("admin"), async (req, res) => {
  await LopHoc.findByIdAndDelete(req.params.id);
  await writeLog(req, req.session.user, "delete:lophoc", "allow", `Xóa lớp ${req.params.id}`);
  res.redirect("/classes");
});

// Xem chi tiết lớp + danh sách sinh viên (giảng viên chỉ xem được lớp mình phụ trách)
router.get("/:id", async (req, res) => {
  const user = req.session.user;
  const lop = await LopHoc.findById(req.params.id)
    .populate("monHocId")
    .populate("giangVienId", "hoTen username")
    .populate("sinhVienIds", "hoTen username khoa");

  if (!lop) return res.status(404).render("error-404");

  const isOwner = user.role === "admin" || String(lop.giangVienId._id) === String(user._id);
  const isMember = user.role === "sinhvien" && lop.sinhVienIds.some((s) => String(s._id) === String(user._id));

  if (!isOwner && !isMember) {
    await writeLog(req, user, "read:lophoc", "deny", "Không thuộc lớp này và không phải giảng viên phụ trách", lop.tenLop);
    return res.status(403).render("error-403", { user, reason: "Bạn không thuộc lớp học này và không phải giảng viên phụ trách." });
  }
  await writeLog(req, user, "read:lophoc", "allow", "Xem chi tiết lớp học", lop.tenLop);

  const allStudents = await User.find({ role: "sinhvien" });
  res.render("classes/detail", { title: lop.tenLop, active: "classes", lop, user, allStudents });
});

router.post("/:id/students/add", requireRole("admin", "giangvien"), async (req, res) => {
  const lop = await LopHoc.findById(req.params.id);
  const user = req.session.user;
  if (user.role === "giangvien" && String(lop.giangVienId) !== String(user._id)) {
    await writeLog(req, user, "update:lophoc", "deny", "Thêm sinh viên vào lớp không phụ trách", lop.tenLop);
    return res.status(403).render("error-403", { user, reason: "Bạn không phụ trách lớp này." });
  }
  await LopHoc.findByIdAndUpdate(req.params.id, { $addToSet: { sinhVienIds: req.body.sinhVienId } });
  await User.findByIdAndUpdate(req.body.sinhVienId, { lopId: req.params.id });
  await writeLog(req, user, "update:lophoc", "allow", "Thêm sinh viên vào lớp", lop.tenLop);
  res.redirect("/classes/" + req.params.id);
});

router.post("/:id/students/:sid/remove", requireRole("admin", "giangvien"), async (req, res) => {
  const lop = await LopHoc.findById(req.params.id);
  const user = req.session.user;
  if (user.role === "giangvien" && String(lop.giangVienId) !== String(user._id)) {
    return res.status(403).render("error-403", { user, reason: "Bạn không phụ trách lớp này." });
  }
  await LopHoc.findByIdAndUpdate(req.params.id, { $pull: { sinhVienIds: req.params.sid } });
  await writeLog(req, user, "update:lophoc", "allow", "Xóa sinh viên khỏi lớp", lop.tenLop);
  res.redirect("/classes/" + req.params.id);
});

module.exports = router;
