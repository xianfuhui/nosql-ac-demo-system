const express = require('express');
const Resource = require('../models/Resource');
const { authMiddleware } = require('../middleware/auth');
const { acMiddleware, makeAccessDecision } = require('../middleware/acEngine');
const AuditLog = require('../models/AuditLog');

const router = express.Router();

/**
 * §2 - GET /api/nosql-types/overview
 * Trả về mô tả 4 loại NoSQL model với ví dụ dữ liệu thực tế trong MongoDB
 */
router.get('/overview', async (req, res) => {
  try {
    const overview = {
      models: [
        {
          type: 'key-value',
          name: 'Key-Value Model',
          section: '§2.1.1',
          description: 'Stores data in schemaless form. Each item has a key (index) and value.',
          useCases: ['Caching', 'Session management', 'Leaderboard'],
          examples: ['Redis', 'DynamoDB', 'Voldemort'],
          mongoSimulation: 'collection: kv_store { _id: key, value: any }',
          acChallenge: 'Access control only at table level (level-2 node)',
        },
        {
          type: 'wide-column',
          name: 'Wide-Column Model',
          section: '§2.1.2',
          description: 'Stores in tables, rows, dynamic columns. Key = row + column + timestamp.',
          useCases: ['IoT data', 'Inventory management', 'Big data processing'],
          examples: ['Cassandra', 'HBase', 'BigTable'],
          mongoSimulation: 'collection per column-family, documents = rows',
          acChallenge: 'Column-level access requires extending tree horizontally',
        },
        {
          type: 'document',
          name: 'Document Model',
          section: '§2.1.3',
          description: 'Stores data as JSON/BSON/XML documents in collections.',
          useCases: ['Blog software', 'Content management', 'Product catalogs', 'Analytics'],
          examples: ['MongoDB', 'CouchDB', 'Firestore'],
          mongoSimulation: 'Native MongoDB document model',
          acChallenge: 'Field-level access requires additional attribute nodes',
        },
        {
          type: 'graph',
          name: 'Graph Model',
          section: '§2.1.4',
          description: 'Stores data as nodes and edges. Schemaless, uses shortest-path algorithms.',
          useCases: ['Recommendation systems', 'Social networking', 'IAM', 'Content management'],
          examples: ['Neo4j', 'Amazon Neptune', 'ArangoDB'],
          mongoSimulation: 'Two collections: graph_nodes + graph_edges',
          acChallenge: 'Most flexible - edges can embed AC rules directly (§3.2.3)',
        },
      ],
      comparison: {
        title: 'Table 1. RDBMS vs NoSQL (§2.2)',
        columns: ['Feature', 'RDBMS', 'NoSQL'],
        rows: [
          ['Database type', 'Relational', 'Non-relational'],
          ['Schema', 'Fixed, structured', 'Dynamic, unstructured'],
          ['Queries', 'Complex JOIN', 'Simple, no JOIN'],
          ['Scalability', 'Vertical', 'Horizontal'],
          ['Properties', 'ACID', 'CAP (eventual consistency)'],
          ['Security', 'Strong built-in', 'Limited, needs add-on'],
          ['Access Control', 'Cell-level (row/column)', 'Coarse-grained (collection)'],
        ],
      },
    };

    // Thêm count thực tế từ MongoDB
    const resourceCounts = await Resource.aggregate([
      { $group: { _id: '$nosqlModel', count: { $sum: 1 } } }
    ]);
    const counts = {};
    resourceCounts.forEach(r => { counts[r._id] = r.count; });
    overview.models.forEach(m => { m.recordCount = counts[m.type] || 0; });

    // Thay ví dụ "structure" viết tay bằng 1 document thật lấy từ MongoDB
    // cho từng loại model (nếu DB đã có seed data)
    await Promise.all(overview.models.map(async (m) => {
      const sample = await Resource.findOne({ nosqlModel: m.type }).lean();
      if (sample) {
        m.structure = {
          source: 'live sample from MongoDB',
          resourceId: sample._id,
          name: sample.name,
          attributes: sample.attributes,
          content: sample.content,
        };
      } else {
        m.structure = { source: 'no document found — run `npm run seed`', example: null };
      }
    }));

    res.json(overview);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/nosql-types/resources - lấy resources theo model type
 */
router.get('/resources', authMiddleware, async (req, res) => {
  try {
    const { nosqlModel, limit = 20 } = req.query;
    const filter = nosqlModel ? { nosqlModel } : {};
    const resources = await Resource.find(filter).limit(parseInt(limit));
    res.json({ resources, total: resources.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/nosql-types/resources/:id - truy cập resource với AC check
 * §4.1 - Demo FGAC: kiểm tra fine-grained access
 */
router.get('/resources/:id', authMiddleware, async (req, res) => {
  try {
    const resource = await Resource.findById(req.params.id);
    if (!resource) return res.status(404).json({ error: 'Resource not found' });

    // Attach object attributes để AC engine dùng
    const subjectAttrs = {
      userId: req.user._id?.toString(),
      role: req.user.attributes?.role,
      department: req.user.attributes?.department,
      group: req.user.attributes?.group,
      organization: req.user.attributes?.organization,
      clearance: req.user.attributes?.clearance,
      roles: req.user.roles || [],
    };

    const objectAttrs = {
      ...resource.attributes,
      type: resource.type,
    };

    const result = await makeAccessDecision(subjectAttrs, objectAttrs, 'read');

    // Ghi audit log §4.6
    await AuditLog.create({
      userId: req.user._id,
      username: req.user.username,
      action: 'read',
      resource: resource.name,
      resourceId: resource._id,
      decision: result.decision,
      matchedPolicy: result.matchedPolicy,
      matchedPolicyId: result.matchedPolicyId,
      subjectAttributes: subjectAttrs,
      objectAttributes: objectAttrs,
      reason: result.reason,
      ipAddress: req.ip,
    });

    if (result.decision === 'deny') {
      return res.status(403).json({
        error: 'Access Denied',
        reason: result.reason,
        resource: { id: resource._id, name: resource.name, type: resource.type },
        acDecision: result,
      });
    }

    res.json({ resource, acDecision: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/nosql-types/resources - tạo resource mới
 */
router.post('/resources', authMiddleware, async (req, res) => {
  try {
    const resource = await Resource.create(req.body);
    res.status(201).json({ resource });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
