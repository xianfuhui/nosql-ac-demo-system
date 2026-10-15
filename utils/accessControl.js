/**
 * Bộ máy kiểm soát truy cập (Policy Engine).
 *
 * Hiện thực hóa mô hình ABAC dạng "đồ thị thuộc tính" mô tả trong bài báo
 * NIST IR 8504 §3.2 - §3.3:
 *   - Mỗi policy là một chuỗi: subject attribute -> action -> object attribute
 *     (xem models/Policy.js, tương ứng Fig. 9 và Fig. 10 của bài báo).
 *   - Quyết định allow/deny được suy ra bằng cách so khớp thuộc tính của
 *     "subject" (người dùng hiện tại) và "object" (tài nguyên muốn truy cập)
 *     với các policy đang active trong collection `policies`.
 *   - Đây chính là minh họa cho §4.1 Fine-Grained Access Control: quyền được
 *     xét tới từng tài nguyên cụ thể (vd 1 lớp học, 1 bản ghi điểm) chứ không
 *     chỉ ở mức toàn database.
 */
const Policy = require("../models/Policy");
const Log = require("../models/Log");

/**
 * resourceCtx mô tả object attribute thực tế của tài nguyên đang truy cập:
 * {
 *   resourceType: 'diem' | 'tailieu' | 'lophoc' | 'monhoc' | 'user' | 'log' | 'policy',
 *   khoa: 'CNTT',
 *   ownerId: <ObjectId của chủ sở hữu, vd sinhVienId của bản ghi điểm>,
 *   assignedTo: [<ObjectId các user được phân công, vd giangVienId của lớp>],
 * }
 */
async function checkAccess(user, action, resourceCtx) {
  const policies = await Policy.find({
    active: true,
    action,
    "objectAttr.resourceType": resourceCtx.resourceType,
  }).sort({ priority: 1 });

  let decision = { allowed: false, matchedPolicy: null, reason: "Không có policy nào khớp (mặc định từ chối)" };

  for (const p of policies) {
    // 1) So khớp thuộc tính subject (role, khoa)
    if (p.subjectAttr.role && p.subjectAttr.role !== user.role) continue;
    if (
      p.subjectAttr.khoa &&
      user.khoa &&
      p.subjectAttr.khoa !== user.khoa
    )
      continue;

    // 2) So khớp thuộc tính object (khoa của tài nguyên)
    if (
      p.objectAttr.khoa &&
      resourceCtx.khoa &&
      p.objectAttr.khoa !== resourceCtx.khoa
    )
      continue;

    // 3) So khớp phạm vi sở hữu / phân công (fine-grained, §4.1)
    if (p.subjectAttr.scope === "own") {
      const ownerId = resourceCtx.ownerId ? String(resourceCtx.ownerId) : null;
      if (!ownerId || ownerId !== String(user._id)) continue;
    }
    if (p.subjectAttr.scope === "assigned") {
      const assignedTo = (resourceCtx.assignedTo || []).map(String);
      if (!assignedTo.includes(String(user._id))) continue;
    }

    // Khớp policy -> áp dụng effect (allow/deny), policy có priority nhỏ nhất thắng
    decision = {
      allowed: p.effect === "allow",
      matchedPolicy: p,
      reason: `Khớp policy "${p.ten}" (scope=${p.subjectAttr.scope}, effect=${p.effect})`,
    };
    break; // đã sort theo priority tăng dần -> policy đầu tiên khớp là policy ưu tiên cao nhất
  }

  return decision;
}

/**
 * Middleware factory: kiểm tra quyền rồi mới cho đi tiếp, đồng thời ghi log
 * (bài báo §4.6 Audit + yêu cầu "ngăn chặn truy cập trái phép").
 *
 * getResourceCtx: async (req) => resourceCtx
 */
function requirePolicy(action, getResourceCtx) {
  return async function (req, res, next) {
    try {
      const user = req.session.user;
      if (!user) {
        await writeLog(req, null, `${action}`, "deny", "Chưa đăng nhập");
        return res.redirect("/login");
      }
      const resourceCtx = await getResourceCtx(req);
      const decision = await checkAccess(user, action, resourceCtx);

      await writeLog(
        req,
        user,
        `${action}:${resourceCtx.resourceType}`,
        decision.allowed ? "allow" : "deny",
        decision.reason,
        resourceCtx.label || ""
      );

      if (!decision.allowed) {
        req.flashError =
          "Bạn không có quyền thực hiện thao tác này (đã bị hệ thống ghi nhận).";
        return res.status(403).render("error-403", {
          user,
          reason: decision.reason,
        });
      }
      req.acDecision = decision;
      next();
    } catch (err) {
      next(err);
    }
  };
}

async function writeLog(req, user, hanhDong, ketQua, chiTiet, doiTuong) {
  try {
    await Log.create({
      nguoiDungId: user ? user._id : null,
      tenDangNhap: user ? user.username : "ẩn danh",
      vaiTro: user ? user.role : null,
      hanhDong,
      doiTuong: doiTuong || "",
      ketQua,
      chiTiet,
      kichBanDemo: req.demoScenario || null,
    });
  } catch (e) {
    console.error("[Log] Ghi log thất bại:", e.message);
  }
}

module.exports = { checkAccess, requirePolicy, writeLog };
