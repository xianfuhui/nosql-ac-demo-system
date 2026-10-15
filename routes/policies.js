const express = require("express");
const router = express.Router();
const { requireRole } = require("../middleware/auth");
const { writeLog } = require("../utils/accessControl");
const Policy = require("../models/Policy");

router.use(requireRole("admin"));

// Quản lý chính sách phân quyền dạng ABAC/graph (bài báo §3.2.3, Fig. 9-10)
router.get("/", async (req, res) => {
  const policies = await Policy.find().sort({ priority: 1 });
  res.render("admin/policies", { title: "Chính sách phân quyền", active: "policies", policies });
});

router.get("/new", (req, res) => {
  res.render("admin/policy-form", { title: "Thêm chính sách", active: "policies", policy: null, error: null });
});

router.post("/", async (req, res) => {
  try {
    const { ten, moTa, role, khoaSubject, scope, action, resourceType, khoaObject, effect, priority } = req.body;
    await Policy.create({
      ten,
      moTa,
      subjectAttr: { role: role || null, khoa: khoaSubject || null, scope: scope || "any" },
      action,
      objectAttr: { resourceType, khoa: khoaObject || null },
      effect,
      priority: Number(priority) || 10,
    });
    await writeLog(req, req.session.user, "create:policy", "allow", `Tạo chính sách "${ten}"`);
    res.redirect("/policies");
  } catch (err) {
    res.render("admin/policy-form", { title: "Thêm chính sách", active: "policies", policy: null, error: err.message });
  }
});

router.get("/:id/edit", async (req, res) => {
  const policy = await Policy.findById(req.params.id);
  res.render("admin/policy-form", { title: "Sửa chính sách", active: "policies", policy, error: null });
});

router.post("/:id", async (req, res) => {
  const { ten, moTa, role, khoaSubject, scope, action, resourceType, khoaObject, effect, priority, active } = req.body;
  await Policy.findByIdAndUpdate(req.params.id, {
    ten,
    moTa,
    subjectAttr: { role: role || null, khoa: khoaSubject || null, scope: scope || "any" },
    action,
    objectAttr: { resourceType, khoa: khoaObject || null },
    effect,
    priority: Number(priority) || 10,
    active: active === "on",
  });
  await writeLog(req, req.session.user, "update:policy", "allow", `Cập nhật chính sách ${req.params.id}`);
  res.redirect("/policies");
});

router.post("/:id/delete", async (req, res) => {
  const p = await Policy.findByIdAndDelete(req.params.id);
  await writeLog(req, req.session.user, "delete:policy", "allow", `Xóa chính sách "${p ? p.ten : req.params.id}"`);
  res.redirect("/policies");
});

router.post("/:id/toggle", async (req, res) => {
  const p = await Policy.findById(req.params.id);
  p.active = !p.active;
  await p.save();
  await writeLog(req, req.session.user, "update:policy", "allow", `${p.active ? 'Bật' : 'Tắt'} chính sách "${p.ten}"`);
  res.redirect("/policies");
});

module.exports = router;
