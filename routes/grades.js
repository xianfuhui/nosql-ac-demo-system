const express = require("express");
const router = express.Router();
const { requireLogin } = require("../middleware/auth");
const { checkAccess, writeLog } = require("../utils/accessControl");

const Diem = require("../models/Diem");
const LopHoc = require("../models/LopHoc");
const LichSuDiem = require("../models/LichSuDiem");

router.use(requireLogin);

// Chức năng #9 Xem điểm (phạm vi theo vai trò) + #8 Nhập/sửa điểm
router.get("/", async (req, res) => {
  const user = req.session.user;
  let grades;
  if (user.role === "admin") {
    grades = await Diem.find().populate("sinhVienId", "hoTen username").populate("monHocId", "tenMon").populate("lopHocId", "tenLop");
  } else if (user.role === "giangvien") {
    const myClasses = await LopHoc.find({ giangVienId: user._id }).select("_id");
    grades = await Diem.find({ lopHocId: { $in: myClasses.map((c) => c._id) } })
      .populate("sinhVienId", "hoTen username")
      .populate("monHocId", "tenMon")
      .populate("lopHocId", "tenLop");
  } else {
    grades = await Diem.find({ sinhVienId: user._id })
      .populate("monHocId", "tenMon")
      .populate("lopHocId", "tenLop");
  }
  res.render("grades/list", { title: "Điểm", active: "grades", grades, user });
});

// Bảng điểm cả lớp — chỉ admin hoặc GV phụ trách lớp đó được nhập/sửa
router.get("/class/:lopId", async (req, res) => {
  const user = req.session.user;
  const lop = await LopHoc.findById(req.params.lopId).populate("monHocId").populate("sinhVienIds", "hoTen username");
  if (!lop) return res.status(404).render("error-404");

  const decision = await checkAccess(user, "update", {
    resourceType: "diem",
    khoa: lop.khoa,
    assignedTo: [lop.giangVienId],
  });

  const canEdit = decision.allowed;

  if (!canEdit && user.role !== "admin" && !(user.role === "sinhvien" && lop.sinhVienIds.some((s) => String(s._id) === String(user._id)))) {
    await writeLog(req, user, "read:diem", "deny", "Không có quyền xem bảng điểm lớp này", lop.tenLop);
    return res.status(403).render("error-403", { user, reason: "Bạn không có quyền xem bảng điểm của lớp này." });
  }

  const diems = await Diem.find({ lopHocId: lop._id }).populate("sinhVienId", "hoTen username");
  const diemMap = {};
  diems.forEach((d) => (diemMap[String(d.sinhVienId._id)] = d));

  await writeLog(req, user, "read:diem", "allow", "Xem bảng điểm lớp", lop.tenLop);
  res.render("grades/class", { title: "Bảng điểm · " + lop.tenLop, active: "grades", lop, diemMap, canEdit, user });
});

router.post("/class/:lopId/update/:sinhVienId", async (req, res) => {
  const user = req.session.user;
  const lop = await LopHoc.findById(req.params.lopId);
  if (!lop) return res.status(404).render("error-404");

  const decision = await checkAccess(user, "update", {
    resourceType: "diem",
    khoa: lop.khoa,
    assignedTo: [lop.giangVienId],
  });

  if (!decision.allowed) {
    await writeLog(req, user, "update:diem", "deny", decision.reason, lop.tenLop);
    return res.status(403).render("error-403", { user, reason: decision.reason });
  }

  let diem = await Diem.findOne({ sinhVienId: req.params.sinhVienId, lopHocId: lop._id });
  if (!diem) {
    diem = await Diem.create({ sinhVienId: req.params.sinhVienId, lopHocId: lop._id, monHocId: lop.monHocId });
  }

  const fields = ["diemChuyenCan", "diemGiuaKy", "diemCuoiKy", "diemTongKet"];
  for (const f of fields) {
    const newValRaw = req.body[f];
    const newVal = newValRaw === "" ? null : Number(newValRaw);
    if (newVal !== diem[f]) {
      await LichSuDiem.create({
        diemId: diem._id,
        sinhVienId: diem.sinhVienId,
        lopHocId: diem.lopHocId,
        truong: f,
        giaTriCu: diem[f],
        giaTriMoi: newVal,
        nguoiSua: user._id,
      });
      diem[f] = newVal;
    }
  }
  diem.capNhatBoi = user._id;
  await diem.save();

  await writeLog(req, user, "update:diem", "allow", `Cập nhật điểm SV ${req.params.sinhVienId}`, lop.tenLop);
  res.redirect("/grades/class/" + lop._id);
});

// Chức năng #14 Xem lịch sử chỉnh sửa điểm
router.get("/history/:diemId", async (req, res) => {
  const user = req.session.user;
  const diem = await Diem.findById(req.params.diemId).populate("lopHocId").populate("sinhVienId", "hoTen username");
  if (!diem) return res.status(404).render("error-404");

  const isOwner = user.role === "sinhvien" && String(diem.sinhVienId._id) === String(user._id);
  const isTeacher = user.role === "giangvien" && String(diem.lopHocId.giangVienId) === String(user._id);
  if (!isOwner && !isTeacher && user.role !== "admin") {
    await writeLog(req, user, "read:lichsu_diem", "deny", "Không có quyền xem lịch sử điểm này");
    return res.status(403).render("error-403", { user, reason: "Bạn không có quyền xem lịch sử điểm này." });
  }

  const history = await LichSuDiem.find({ diemId: diem._id }).populate("nguoiSua", "hoTen username").sort({ thoiGian: -1 });
  await writeLog(req, user, "read:lichsu_diem", "allow", "Xem lịch sử sửa điểm", diem.sinhVienId.hoTen);
  res.render("grades/history", { title: "Lịch sử sửa điểm", active: "grades", diem, history, user });
});

module.exports = router;
