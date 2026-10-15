const express = require("express");
const router = express.Router();
const { requireLogin, requireRole } = require("../middleware/auth");
const { writeLog } = require("../utils/accessControl");
const User = require("../models/User");
const LopHoc = require("../models/LopHoc");

router.use(requireLogin, requireRole("admin", "giangvien"));

// Chức năng #4 Quản lý hồ sơ sinh viên
// Admin: xem/sửa tất cả. Giảng viên: chỉ xem sinh viên thuộc lớp mình phụ trách (FGAC §4.1)
router.get("/", async (req, res) => {
  const user = req.session.user;
  let students;
  if (user.role === "admin") {
    students = await User.find({ role: "sinhvien" }).populate("lopId", "tenLop maLop");
  } else {
    const myClasses = await LopHoc.find({ giangVienId: user._id });
    const studentIds = [...new Set(myClasses.flatMap((c) => c.sinhVienIds.map(String)))];
    students = await User.find({ _id: { $in: studentIds } }).populate("lopId", "tenLop maLop");
  }
  res.render("students/list", { title: "Hồ sơ sinh viên", active: "students", students, user });
});

router.get("/:id", async (req, res) => {
  const user = req.session.user;
  const student = await User.findById(req.params.id).populate("lopId");
  if (!student || student.role !== "sinhvien") return res.status(404).render("error-404");

  if (user.role === "giangvien") {
    const myClasses = await LopHoc.find({ giangVienId: user._id, sinhVienIds: student._id });
    if (myClasses.length === 0) {
      await writeLog(req, user, "read:hoso_sv", "deny", "Sinh viên không thuộc lớp phụ trách", student.hoTen);
      return res.status(403).render("error-403", { user, reason: "Sinh viên này không thuộc lớp bạn phụ trách." });
    }
  }
  await writeLog(req, user, "read:hoso_sv", "allow", "Xem hồ sơ sinh viên", student.hoTen);
  res.render("students/detail", { title: student.hoTen, active: "students", student, user });
});

router.post("/:id", requireRole("admin"), async (req, res) => {
  const { hoTen, email, khoa } = req.body;
  await User.findByIdAndUpdate(req.params.id, { hoTen, email, khoa });
  await writeLog(req, req.session.user, "update:hoso_sv", "allow", `Cập nhật hồ sơ SV ${req.params.id}`);
  res.redirect("/students/" + req.params.id);
});

module.exports = router;
