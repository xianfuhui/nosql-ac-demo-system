const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const { requireRole } = require("../middleware/auth");
const { writeLog } = require("../utils/accessControl");

const User = require("../models/User");
const LopHoc = require("../models/LopHoc");
const MonHoc = require("../models/MonHoc");

// Chức năng #2 Quản lý tài khoản + #3 Phân quyền người dùng — chỉ Admin
router.use(requireRole("admin"));

router.get("/", async (req, res) => {
  const users = await User.find().sort({ role: 1, username: 1 });
  res.render("admin/accounts", { title: "Tài khoản & Phân quyền", active: "accounts", users });
});

router.get("/new", async (req, res) => {
  const lopHocs = await LopHoc.find();
  const monHocs = await MonHoc.find();
  res.render("admin/account-form", {
    title: "Thêm tài khoản",
    active: "accounts",
    account: null,
    lopHocs,
    monHocs,
    error: null,
  });
});

router.post("/", async (req, res) => {
  try {
    const { username, password, hoTen, email, role, khoa, lopId, lopPhuTrach, monPhuTrach } = req.body;
    const passwordHash = await bcrypt.hash(password || "123456", 10);
    const user = await User.create({
      username,
      passwordHash,
      hoTen,
      email,
      role,
      khoa: khoa || null,
      lopId: role === "sinhvien" ? lopId || null : null,
      lopPhuTrach: role === "giangvien" ? [].concat(lopPhuTrach || []).filter(Boolean) : [],
      monPhuTrach: role === "giangvien" ? [].concat(monPhuTrach || []).filter(Boolean) : [],
    });
    await writeLog(req, req.session.user, "create:user", "allow", `Tạo tài khoản ${username} (${role})`);
    res.redirect("/accounts");
  } catch (err) {
    const lopHocs = await LopHoc.find();
    const monHocs = await MonHoc.find();
    res.render("admin/account-form", {
      title: "Thêm tài khoản",
      active: "accounts",
      account: null,
      lopHocs,
      monHocs,
      error: "Lỗi: " + err.message,
    });
  }
});

router.get("/:id/edit", async (req, res) => {
  const account = await User.findById(req.params.id);
  const lopHocs = await LopHoc.find();
  const monHocs = await MonHoc.find();
  res.render("admin/account-form", {
    title: "Sửa tài khoản",
    active: "accounts",
    account,
    lopHocs,
    monHocs,
    error: null,
  });
});

router.post("/:id", async (req, res) => {
  const { hoTen, email, role, khoa, lopId, lopPhuTrach, monPhuTrach, active, newPassword } = req.body;
  const update = {
    hoTen,
    email,
    role,
    khoa: khoa || null,
    lopId: role === "sinhvien" ? lopId || null : null,
    lopPhuTrach: role === "giangvien" ? [].concat(lopPhuTrach || []).filter(Boolean) : [],
    monPhuTrach: role === "giangvien" ? [].concat(monPhuTrach || []).filter(Boolean) : [],
    active: active === "on",
  };
  if (newPassword) update.passwordHash = await bcrypt.hash(newPassword, 10);

  await User.findByIdAndUpdate(req.params.id, update);
  await writeLog(req, req.session.user, "update:user", "allow", `Cập nhật tài khoản ID ${req.params.id}`);
  res.redirect("/accounts");
});

router.post("/:id/delete", async (req, res) => {
  const u = await User.findByIdAndDelete(req.params.id);
  await writeLog(req, req.session.user, "delete:user", "allow", `Xóa tài khoản ${u ? u.username : req.params.id}`);
  res.redirect("/accounts");
});

module.exports = router;
