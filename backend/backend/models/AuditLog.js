const mongoose = require('mongoose');

// §4.6 - Audit log mọi access attempt
const AuditLogSchema = new mongoose.Schema({
  timestamp:  { type: Date, default: Date.now },
  userId:     { type: String },
  username:   { type: String },
  action:     { type: String }, // read, write, delete...
  resource:   { type: String },
  resourceId: { type: String },
  decision:   { type: String, enum: ['allow', 'deny'], required: true },
  // Policy nào đã quyết định
  matchedPolicy:    { type: String },
  matchedPolicyId:  { type: String },
  // Chi tiết để debug
  subjectAttributes:{ type: mongoose.Schema.Types.Mixed },
  objectAttributes: { type: mongoose.Schema.Types.Mixed },
  reason:     { type: String },
  ipAddress:  { type: String },
  userAgent:  { type: String },
});

// Index để query nhanh
AuditLogSchema.index({ timestamp: -1 });
AuditLogSchema.index({ userId: 1, timestamp: -1 });
AuditLogSchema.index({ decision: 1 });

module.exports = mongoose.model('AuditLog', AuditLogSchema);
