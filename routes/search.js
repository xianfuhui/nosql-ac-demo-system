const express = require("express");
const router = express.Router();
const { requireLogin } = require("../middleware/auth");
const { writeLog } = require("../utils/accessControl");

const User = require("../models/User");
const MonHoc = require("../models/MonHoc");
const LopHoc = require("../models/LopHoc");

router.use(requireLogin);

// Chức năng #12 Tìm kiếm dữ liệu — chỉ trả về dữ liệu người dùng có quyền xem.
// Input q được mongoSanitize làm sạch trước đó (chống NoSQL Injection §4.2).
router.get("/", async (req, res) => {
  const user = req.session.user;
  const q = (req.query.q || "").toString().trim();
  let students = [],
    courses = [],
    classes = [];

  if (q) {
    const regex = new RegExp(escapeRegex(q), "i");

    if (user.role === "admin") {
      students = await User.find({ role: "sinhvien", $or: [{ hoTen: regex }, { username: regex }] }).limit(20);
      courses = await MonHoc.find({ $or: [{ tenMon: regex }, { maMon: regex }] }).limit(20);
      classes = await LopHoc.find({ $or: [{ tenLop: regex }, { maLop: regex }] }).limit(20);
    } else if (user.role === "giangvien") {
      const myClasses = await LopHoc.find({ giangVienId: user._id });
      const myStudentIds = [...new Set(myClasses.flatMap((c) => c.sinhVienIds.map(String)))];
      students = await User.find({
        _id: { $in: myStudentIds },
        $or: [{ hoTen: regex }, { username: regex }],
      }).limit(20);
      courses = await MonHoc.find({ giangVienIds: user._id, $or: [{ tenMon: regex }, { maMon: regex }] }).limit(20);
      classes = myClasses.filter((c) => regex.test(c.tenLop) || regex.test(c.maLop));
    } else {
      // Sinh viên: chỉ tìm trong lớp mình học, không thấy sinh viên khác
      courses = await MonHoc.find({ $or: [{ tenMon: regex }, { maMon: regex }] }).limit(20);
      classes = user.lopId
        ? await LopHoc.find({ _id: user.lopId, $or: [{ tenLop: regex }, { maLop: regex }] })
        : [];
    }

    await writeLog(
      req,
      user,
      "search",
      "allow",
      `Từ khóa: "${q}" — Kết quả bị giới hạn theo phạm vi quyền (${students.length} SV, ${courses.length} môn, ${classes.length} lớp)`
    );
  }

  res.render("search/results", { title: "Tìm kiếm", active: "search", q, students, courses, classes, user });
});

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = router;
