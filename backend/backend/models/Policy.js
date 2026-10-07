const mongoose = require('mongoose');

// §3 - Access Control Policy Rule
// Formal: {database, subject_attributes, leaf_subject(opt), object_attributes, leaf_object(opt), actions, permission}
const PolicySchema = new mongoose.Schema({
  name:        { type: String, required: true },
  description: { type: String },
  policyType:  { type: String, enum: ['ABAC', 'RBAC', 'DAC', 'MAC'], default: 'ABAC' },
  nosqlModel:  { type: String, enum: ['key-value', 'wide-column', 'document', 'graph', 'all'], default: 'all' },
  effect:      { type: String, enum: ['allow', 'deny'], default: 'allow' },

  // Subject conditions (§3.2 - subject attributes)
  subjectConditions: {
    role:         { type: String },
    department:   { type: String },
    group:        { type: String },
    organization: { type: String },
    minClearance: { type: Number },
    userId:       { type: String }, // for DAC
  },

  // Object conditions (§3.2 - object attributes)
  objectConditions: {
    company:        { type: String },
    branch:         { type: String },
    division:       { type: String },
    department:     { type: String },
    classification: { type: String },
    maxSensitivity: { type: Number },
    resourceType:   { type: String },
  },

  // Permitted actions
  actions: [{
    type: String,
    enum: ['read', 'write', 'update', 'delete', 'execute', 'admin']
  }],

  // Environment conditions (§4.7)
  environmentConditions: {
    timeFrom:    { type: String }, // "08:00"
    timeTo:      { type: String }, // "18:00"
    ipWhitelist: [{ type: String }],
    requireMFA:  { type: Boolean, default: false },
  },

  // Natural language rule (sinh ra từ §4.8 AI hoặc do user nhập)
  naturalLanguageRule: { type: String },

  priority: { type: Number, default: 0 }, // higher = evaluated first
  isActive: { type: Boolean, default: true },
  createdBy:{ type: String },
  createdAt:{ type: Date, default: Date.now },
});

module.exports = mongoose.model('Policy', PolicySchema);
