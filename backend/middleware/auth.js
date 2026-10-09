const jwt = require('jsonwebtoken');
const User = require('../models/User');

const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const secret = process.env.JWT_SECRET || 'dev_secret_change_in_production';
    const decoded = jwt.verify(token, secret);

    const user = await User.findById(decoded.userId).select('-password');
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'User not found or inactive' });
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Optional auth - không bắt buộc nhưng attach user nếu có token
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev_secret_change_in_production');
      const user = await User.findById(decoded.userId).select('-password');
      if (user && user.isActive) req.user = user;
    }
  } catch (err) { /* ignore */ }
  next();
};

// Chặn thật ở server (không chỉ ẩn UI) - dùng để tách khu vực Admin / User.
// Phải đứng sau authMiddleware (cần req.user).
const requireAdmin = (req, res, next) => {
  const role = req.user?.attributes?.role;
  const isAdmin = role === 'admin' || (req.user?.roles || []).includes('admin');
  if (!isAdmin) {
    return res.status(403).json({
      error: 'Admin role required for this action',
      yourRole: role || 'unknown',
      hint: 'Đăng nhập bằng tài khoản có attributes.role = "admin" (vd: admin/admin123) để thực hiện thao tác này.',
    });
  }
  next();
};

module.exports = { authMiddleware, optionalAuth, requireAdmin };
