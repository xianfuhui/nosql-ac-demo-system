/** Middleware xác thực phiên đăng nhập và phân quyền theo vai trò (RBAC cơ bản). */

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.session.user) return res.redirect("/login");
    if (!roles.includes(req.session.user.role)) {
      return res.status(403).render("error-403", {
        user: req.session.user,
        reason: `Chức năng này chỉ dành cho vai trò: ${roles.join(", ")}`,
      });
    }
    next();
  };
}

/** Gắn user (nếu có) + danh sách thông báo flash vào mọi view. */
function attachLocals(req, res, next) {
  res.locals.currentUser = req.session.user || null;
  next();
}

module.exports = { requireLogin, requireRole, attachLocals };
