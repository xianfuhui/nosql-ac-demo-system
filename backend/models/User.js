const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// §3.2 - Subject attributes theo bài báo NIST IR 8504
const UserSchema = new mongoose.Schema({
  // Leaf node (level 3 trong tree structure)
  username: { type: String, required: true, unique: true, trim: true },
  email:    { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },

  // Subject attributes (node level 2-4 trong hierarchical tree - Fig.5)
  attributes: {
    role:        { type: String, enum: ['admin', 'manager', 'employee', 'guest'], default: 'guest' },
    department:  { type: String, default: 'general' },   // level-2 node (Table/Column family)
    group:       { type: String, default: 'default' },   // level-3 node (Key/Row)
    organization:{ type: String, default: 'default' },   // level-2 node (Collection)
    clearance:   { type: Number, min: 0, max: 5, default: 1 }, // for MAC demo
    location:    { type: String, default: 'HQ' },
  },

  // RBAC roles (§3.2 - role-based layer)
  roles: [{ type: String }],

  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
});

// Hash password trước khi lưu
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// So sánh password
UserSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Trả về object không có password
UserSchema.methods.toPublic = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

module.exports = mongoose.model('User', UserSchema);
