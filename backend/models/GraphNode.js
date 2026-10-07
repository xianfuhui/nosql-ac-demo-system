const mongoose = require('mongoose');

// §3.2.3 - Graph NoSQL model: nodes lưu data entities
const GraphNodeSchema = new mongoose.Schema({
  nodeId:   { type: String, required: true, unique: true },
  label:    { type: String, required: true }, // 'user', 'group', 'company', 'file', 'department', 'organization'
  name:     { type: String, required: true },
  nodeType: { type: String, enum: ['subject', 'object', 'attribute', 'action'], required: true },
  data:     { type: mongoose.Schema.Types.Mixed, default: {} },
  createdAt:{ type: Date, default: Date.now },
});

// §3.2.3 - Graph NoSQL model: edges lưu relationships/actions
const GraphEdgeSchema = new mongoose.Schema({
  edgeId:       { type: String, required: true, unique: true },
  fromNodeId:   { type: String, required: true },
  toNodeId:     { type: String, required: true },
  // Edge có thể là attribute ("in", "works for", "belongs to") hoặc permitted action ("can read") - §3.2.3
  relationship: { type: String, required: true }, // e.g. "in", "works_for", "belongs_to", "can_read", "can_write"
  edgeType:     { type: String, enum: ['attribute', 'action'], default: 'attribute' },
  // Nếu là action edge → embedded AC policy (§3.2.3 Fig.10)
  isACRule:     { type: Boolean, default: false },
  data:         { type: mongoose.Schema.Types.Mixed, default: {} },
  createdAt:    { type: Date, default: Date.now },
});

const GraphNode = mongoose.model('GraphNode', GraphNodeSchema);
const GraphEdge = mongoose.model('GraphEdge', GraphEdgeSchema);

module.exports = { GraphNode, GraphEdge };
