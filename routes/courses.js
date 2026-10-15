const express = require("express");
const router = express.Router();
const { requireLogin, requireRole } = require("../middleware/auth");
const { writeLog } = require("../utils/accessControl");
const MonHoc = require("../models/MonHoc");
const User = require("../models/User");

router.use(requireLogin);

// Chức năng #6 Quản lý môn học — Admin toàn quyền, giảng viên xem môn mình phụ trách
router.get("/", async (req, res) => {
  const user = req.session.user;
  const filter = user.role === "admin" ? {} : { giangVienIds: user._id };
  const courses = await MonHoc.find(filter).populate("giangVienIds", "hoTen username");
  res.render("courses/list", { title: "Môn học", active: "courses", courses, user });
});

router.get("/new", requireRole("admin"), async (req, res) => {
  const giangViens = await User.find({ role: "giangvien" });
  res.render("courses/form", { title: "Thêm môn học", active: "courses", course: null, giangViens, error: null });
});

router.post("/", requireRole("admin"), async (req, res) => {
  try {
    const { maMon, tenMon, khoa, soTinChi, giangVienIds } = req.body;
    await MonHoc.create({
      maMon,
      tenMon,
      khoa,
      soTinChi: Number(soTinChi) || 3,
      giangVienIds: [].concat(giangVienIds || []).filter(Boolean),
    });
    await writeLog(req, req.session.user, "create:monhoc", "allow", `Tạo môn học ${maMon} - ${tenMon}`);
    res.redirect("/courses");
  } catch (err) {
    const giangViens = await User.find({ role: "giangvien" });
    res.render("courses/form", { title: "Thêm môn học", active: "courses", course: null, giangViens, error: err.message });
  }
});

router.get("/:id/edit", requireRole("admin"), async (req, res) => {
  const course = await MonHoc.findById(req.params.id);
  const giangViens = await User.find({ role: "giangvien" });
  res.render("courses/form", { title: "Sửa môn học", active: "courses", course, giangViens, error: null });
});

router.post("/:id", requireRole("admin"), async (req, res) => {
  const { tenMon, khoa, soTinChi, giangVienIds } = req.body;
  await MonHoc.findByIdAndUpdate(req.params.id, {
    tenMon,
    khoa,
    soTinChi: Number(soTinChi) || 3,
    giangVienIds: [].concat(giangVienIds || []).filter(Boolean),
  });
  await writeLog(req, req.session.user, "update:monhoc", "allow", `Cập nhật môn học ${req.params.id}`);
  res.redirect("/courses");
});

router.post("/:id/delete", requireRole("admin"), async (req, res) => {
  await MonHoc.findByIdAndDelete(req.params.id);
  await writeLog(req, req.session.user, "delete:monhoc", "allow", `Xóa môn học ${req.params.id}`);
  res.redirect("/courses");
});

module.exports = router;
