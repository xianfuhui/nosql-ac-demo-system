const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const { writeLog } = require("../utils/accessControl");

router.get("/login", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  res.render("auth/login", { error: null });
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body; // đã qua mongoSanitize chống NoSQL injection
  try {
    const user = await User.findOne({ username, active: true });
    const ok = user && (await bcrypt.compare(password || "", user.passwordHash));

    if (!ok) {
      await writeLog(
        req,
        user || { username, role: "?" },
        "login",
        "fail",
        "Sai tên đăng nhập hoặc mật khẩu"
      );
      return res.render("auth/login", {
        error: "Sai tên đăng nhập hoặc mật khẩu.",
      });
    }

    req.session.user = {
      _id: user._id,
      username: user.username,
      hoTen: user.hoTen,
      role: user.role,
      khoa: user.khoa,
      lopId: user.lopId,
      lopPhuTrach: user.lopPhuTrach,
      monPhuTrach: user.monPhuTrach,
    };
    await writeLog(req, user, "login", "success", "Đăng nhập thành công");
    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.render("auth/login", { error: "Có lỗi xảy ra, vui lòng thử lại." });
  }
});

router.post("/logout", async (req, res) => {
  const user = req.session.user;
  if (user) await writeLog(req, user, "logout", "success", "Đăng xuất");
  req.session.destroy(() => res.redirect("/login"));
});

// Đăng nhập nhanh cho tài khoản demo (mỗi tài khoản test -> phiên riêng để minh họa)
router.get("/login-as/:username", async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username, active: true });
    if (!user) return res.redirect("/login");
    req.session.user = {
      _id: user._id,
      username: user.username,
      hoTen: user.hoTen,
      role: user.role,
      khoa: user.khoa,
      lopId: user.lopId,
      lopPhuTrach: user.lopPhuTrach,
      monPhuTrach: user.monPhuTrach,
    };
    await writeLog(req, user, "login", "success", "Đăng nhập nhanh (demo account)");
    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.redirect("/login");
  }
});

module.exports = router;
