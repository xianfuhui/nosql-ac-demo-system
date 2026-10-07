const mongoose = require('mongoose');

// §3.2 - Object attributes theo từng NoSQL model (Fig.7, 8, 9)
const ResourceSchema = new mongoose.Schema({
  name:        { type: String, required: true },
  type:        { type: String, enum: ['file', 'collection', 'table', 'document', 'record', 'api'], default: 'file' },
  description: { type: String },

  // Mô phỏng object attributes theo hierarchical tree (§3.2.1 - §3.2.2)
  attributes: {
    // Key-Value model: value=file, key=branch, table=company
    company:    { type: String, default: 'default' },   // level-2 (Table)
    branch:     { type: String, default: 'main' },      // level-3 (Key)
    // Wide-Column / Document model
    division:   { type: String, default: 'general' },   // level-3 (Row/Document)
    department: { type: String, default: 'general' },   // level-4 (Column-ID/Field)
    // Sensitivity level (cho MAC - §4.2)
    sensitivity:  { type: Number, min: 0, max: 5, default: 1 },
    classification: { type: String, enum: ['public', 'internal', 'confidential', 'secret'], default: 'internal' },
    owner:      { type: String, default: 'system' },
  },

  // Dữ liệu giả lập của resource
  content:   { type: mongoose.Schema.Types.Mixed, default: {} },
  nosqlModel:{ type: String, enum: ['key-value', 'wide-column', 'document', 'graph'], default: 'document' },

  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Resource', ResourceSchema);
