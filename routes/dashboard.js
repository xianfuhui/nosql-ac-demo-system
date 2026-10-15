const express = require("express");
const router = express.Router();
const { requireLogin } = require("../middleware/auth");

const User = require("../models/User");
const MonHoc = require("../models/MonHoc");
const LopHoc = require("../models/LopHoc");
const Diem = require("../models/Diem");
const TaiLieu = require("../models/TaiLieu");
const Log = require("../models/Log");

router.get("/", (req, res) => res.redirect(req.session.user ? "/dashboard" : "/login"));

router.get("/dashboard", requireLogin, async (req, res) => {
  const user = req.session.user;
  const stats = {};
  let recentLogs = [];

  if (user.role === "admin") {
    stats.soTaiKhoan = await User.countDocuments();
    stats.soMonHoc = await MonHoc.countDocuments();
    stats.soLopHoc = await LopHoc.countDocuments();
    stats.soTaiLieu = await TaiLieu.countDocuments();
    recentLogs = await Log.find().sort({ thoiGian: -1 }).limit(8);
  } else if (user.role === "giangvien") {
    stats.soLopPhuTrach = await LopHoc.countDocuments({ giangVienId: user._id });
    const lops = await LopHoc.find({ giangVienId: user._id });
    const tongSv = lops.reduce((s, l) => s + (l.sinhVienIds?.length || 0), 0);
    stats.soSinhVien = tongSv;
    stats.soTaiLieu = await TaiLieu.countDocuments({ nguoiTaiLen: user._id });
    recentLogs = await Log.find({ nguoiDungId: user._id }).sort({ thoiGian: -1 }).limit(8);
  } else {
    const diems = await Diem.find({ sinhVienId: user._id }).populate("monHocId");
    stats.soMonDaHoc = diems.length;
    const coTongKet = diems.filter((d) => d.diemTongKet != null);
    stats.diemTrungBinh =
      coTongKet.length > 0
        ? (coTongKet.reduce((s, d) => s + d.diemTongKet, 0) / coTongKet.length).toFixed(2)
        : "—";
    stats.soTaiLieu = await TaiLieu.countDocuments({ lopHocId: user.lopId });
    recentLogs = await Log.find({ nguoiDungId: user._id }).sort({ thoiGian: -1 }).limit(8);
  }

  res.render("dashboard", { title: "Trang chủ", active: "dashboard", user, stats, recentLogs });
});

module.exports = router;
