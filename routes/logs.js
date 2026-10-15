const express = require("express");
const router = express.Router();
const { requireRole } = require("../middleware/auth");
const Log = require("../models/Log");

router.use(requireRole("admin"));

// Chức năng #13 Ghi nhật ký hoạt động — Admin xem toàn bộ log
router.get("/", async (req, res) => {
  const filter = {};
  if (req.query.ketQua) filter.ketQua = req.query.ketQua;
  if (req.query.user) filter.tenDangNhap = req.query.user;

  const logs = await Log.find(filter).sort({ thoiGian: -1 }).limit(300);
  res.render("logs/list", { title: "Nhật ký hệ thống", active: "logs", logs, filter: req.query });
});

module.exports = router;
