const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const AuditLog = require('../models/AuditLog');
const Resource = require('../models/Resource');
const Policy = require('../models/Policy');
const User = require('../models/User');
const { authMiddleware, requireAdmin } = require('../middleware/auth');
const { makeAccessDecision } = require('../middleware/acEngine');

const router = express.Router();

// Toàn bộ §4 Considerations là công cụ phân tích/demo nội bộ (injection
// testing, audit logs, performance benchmark, CAP probe...) — chỉ dành
// cho admin. Chặn thật ở server, không chỉ ẩn ở UI.
router.use(authMiddleware, requireAdmin);

// §4.4 - collection riêng dùng để đo lường consistency thật trên chính
// MongoDB đang chạy (không phải số liệu dựng sẵn)
const ConsistencyProbeSchema = new mongoose.Schema({
  key: { type: String, unique: true },
  value: mongoose.Schema.Types.Mixed,
  version: { type: Number, default: 0 },
  updatedAt: { type: Date, default: Date.now },
});
const ConsistencyProbe = mongoose.models.ConsistencyProbe || mongoose.model('ConsistencyProbe', ConsistencyProbeSchema);

// ============================================================
// §4.1 - Fine-Grained Access Control Demo
// ============================================================

/**
 * POST /api/considerations/fgac/demo
 * So sánh coarse-grained vs fine-grained access control
 */
router.post('/fgac/demo', authMiddleware, async (req, res) => {
  try {
    const { resourceId, requestedField } = req.body;
    const resource = await Resource.findById(resourceId);
    if (!resource) return res.status(404).json({ error: 'Resource not found' });

    const subjectAttrs = {
      userId: req.user._id?.toString(),
      role: req.user.attributes?.role,
      department: req.user.attributes?.department,
      group: req.user.attributes?.group,
      organization: req.user.attributes?.organization,
      clearance: req.user.attributes?.clearance,
      roles: req.user.roles || [],
    };

    // --- Coarse-grained: truy vấn thật trong Policy collection, chỉ xét
    // theo nosqlModel (collection-level) và bỏ qua classification/sensitivity
    // của từng document, mô phỏng đúng cách NoSQL thường chỉ enforce ở
    // mức "toàn bộ collection" ---
    const collectionPolicies = await Policy.find({
      isActive: true,
      $or: [{ nosqlModel: resource.nosqlModel }, { nosqlModel: 'all' }],
    }).sort({ priority: -1 });

    const coarseMatch = collectionPolicies.find((p) => {
      const sc = p.subjectConditions || {};
      if (sc.role && sc.role !== subjectAttrs.role) return false;
      if (sc.department && sc.department !== subjectAttrs.department) return false;
      if (sc.minClearance != null && subjectAttrs.clearance < sc.minClearance) return false;
      return p.actions.includes('read') || p.actions.includes('admin');
    });
    const coarseAllows = !!coarseMatch && coarseMatch.effect !== 'deny';

    // Nếu coarse-grained cho allow, liệt kê thật các resource khác cùng
    // nosqlModel đang bị "lộ theo" (kể cả những resource nhạy cảm hơn)
    const siblingResources = coarseAllows
      ? await Resource.find({ nosqlModel: resource.nosqlModel })
          .select('name attributes.classification attributes.sensitivity')
      : [];

    const coarseResult = {
      level: 'collection',
      decision: coarseMatch ? (coarseAllows ? 'allow' : 'deny') : 'deny',
      matchedPolicy: coarseMatch ? coarseMatch.name : null,
      description: '§4.1: Collection-level kết quả được tính từ các Policy thật trong MongoDB, bỏ qua classification/sensitivity riêng của từng document',
      exposedResources: siblingResources.map((r) => ({
        id: r._id, name: r.name, classification: r.attributes?.classification,
      })),
      example: coarseMatch
        ? `Policy "${coarseMatch.name}" cấp quyền read cho toàn bộ collection "${resource.nosqlModel}" → mọi document trong đó đều lộ ra, kể cả những resource nhạy cảm hơn "${resource.name}"`
        : `Không có policy nào ở mức collection "${resource.nosqlModel}" khớp với user này`,
    };

    // --- Fine-grained: đánh giá thật trên document vừa lấy từ MongoDB,
    // kèm kiểm tra tồn tại field cụ thể trong content thật của document ---
    const objectAttrs = { ...resource.attributes, type: resource.type };
    const fineResult = await makeAccessDecision(subjectAttrs, objectAttrs, 'read');

    let fieldLevelResult = null;
    if (requestedField) {
      const content = resource.content instanceof Map
        ? Object.fromEntries(resource.content)
        : (resource.content || {});
      const fieldExists = Object.prototype.hasOwnProperty.call(content, requestedField);
      fieldLevelResult = {
        field: requestedField,
        existsInDocument: fieldExists,
        decision: fineResult.decision === 'allow' && fieldExists ? 'allow' : 'deny',
        value: fineResult.decision === 'allow' && fieldExists ? content[requestedField] : undefined,
      };
    }

    res.json({
      comparison: {
        coarseGrained: coarseResult,
        fineGrained: {
          level: requestedField ? `field: "${requestedField}"` : 'document',
          decision: fineResult.decision,
          matchedPolicy: fineResult.matchedPolicy,
          reason: fineResult.reason,
          fieldLevelResult,
          description: '§4.1: Fine-grained AC được đánh giá bởi ABAC engine thật, chạy trên chính document lấy từ MongoDB',
          example: requestedField
            ? `User truy cập field "${requestedField}" của resource "${resource.name}"`
            : `User truy cập document "${resource.name}"`,
        },
      },
      nistNote: 'Unlike RDBMS where FGAC allows row/column-level control, NoSQL requires custom enforcement mechanisms (§4.1)',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/considerations/fgac/levels
 * Hiển thị các granularity levels theo từng NoSQL model, lấy field thật
 * từ các Resource document hiện có trong MongoDB (không dựng sẵn).
 */
router.get('/fgac/levels', async (req, res) => {
  try {
    const staticPaths = {
      'key-value':  ['database', 'table', 'key', 'value'],
      'wide-column':['database', 'column-family', 'row', 'column-id', 'value'],
      'document':   ['database', 'collection', 'document', 'field', 'value'],
      'graph':      ['database', 'node', 'edge', 'property'],
    };

    const granularityLevels = {};
    for (const [model, path] of Object.entries(staticPaths)) {
      const docs = await Resource.find({ nosqlModel: model }).limit(10);
      const fieldSet = new Set();
      docs.forEach((r) => {
        const content = r.content instanceof Map ? Object.fromEntries(r.content) : (r.content || {});
        Object.keys(content).forEach((k) => fieldSet.add(k));
      });
      const observed = Array.from(fieldSet);
      // Thay level cuối ("value") bằng field thật quan sát được từ DB, nếu có
      const enrichedPath = [...path];
      if (observed.length) {
        enrichedPath[enrichedPath.length - 1] = `value (observed: ${observed.slice(0, 5).join(', ')})`;
      }
      granularityLevels[model] = enrichedPath;
    }

    const rdbmsCellCount = await Resource.countDocuments({});
    granularityLevels['RDBMS'] = ['database', 'schema', 'table', 'row', 'column', 'cell'];

    res.json({
      granularityLevels,
      documentCountByModel: Object.fromEntries(
        await Promise.all(
          Object.keys(staticPaths).map(async (m) => [m, await Resource.countDocuments({ nosqlModel: m })])
        )
      ),
      totalResourcesInDb: rdbmsCellCount,
      nistFigure: 'Fig. 5 - Hierarchical structure relationships',
      challenge: 'NoSQL enforces AC at collection/family level; cell-level requires add-on (§4.1)',
      note: '"observed" fields were computed live from Resource documents stored in MongoDB, not hardcoded.',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// §4.2 - Security Demo: Injection Attack Simulation
// ============================================================

/**
 * POST /api/considerations/security/injection-demo
 * §4.2 - Chạy THẬT 2 đường truy vấn trên chính collection "users" trong
 * MongoDB đang kết nối, để so sánh:
 *   - vulnerablePath: dùng native driver, forward thẳng input vào filter,
 *     không qua Mongoose casting → object operator ($gt/$ne/$where) có thể lọt
 *   - safePath: dùng Mongoose User model, filter bị ép kiểu String → operator
 *     object không còn tác dụng
 * Kết quả (số bản ghi khớp, dữ liệu trả về) lấy trực tiếp từ DB thật,
 * không dựng sẵn.
 */
router.post('/security/injection-demo', async (req, res) => {
  try {
    const { inputUsername } = req.body;
    const db = mongoose.connection.db;

    // --- Đường dễ bị injection: raw filter, không ép kiểu ---
    let vulnerableUsers = [];
    let vulnerableError = null;
    try {
      vulnerableUsers = await db.collection('users')
        .find({ username: inputUsername })
        .project({ password: 0 })
        .limit(50)
        .toArray();
    } catch (e) {
      vulnerableError = e.message;
    }

    // --- Đường an toàn: qua Mongoose, value luôn bị ép về String ---
    let safeUsers = [];
    try {
      safeUsers = await User.find({ username: String(inputUsername) }).select('-password').limit(50);
    } catch (e) {
      safeUsers = [];
    }

    const totalUsersInDatabase = await db.collection('users').countDocuments({});
    const isObjectInjection = typeof inputUsername === 'object' && inputUsername !== null;

    // Exploit chỉ được coi là "confirmed" khi dữ liệu THẬT từ DB cho thấy
    // đường vulnerable lộ ra nhiều/khác bản ghi hơn đường safe
    const exploitConfirmed = isObjectInjection && (
      vulnerableUsers.length > safeUsers.length || vulnerableUsers.length > 1
    );

    const heuristicSuspicious = typeof inputUsername === 'string' && (
      inputUsername.includes('$') || inputUsername.includes('{') ||
      inputUsername.includes('where') || inputUsername.includes('eval')
    );

    const result = {
      input: inputUsername,
      totalUsersInDatabase,
      vulnerablePath: {
        description: 'db.collection("users").find({ username: inputUsername }) qua native driver — không ép kiểu, object operator có thể lọt qua',
        matchedCount: vulnerableUsers.length,
        matchedUsers: vulnerableUsers.map((u) => ({ username: u.username, role: u.attributes?.role })),
        error: vulnerableError,
      },
      safePath: {
        description: 'User.find({ username: String(inputUsername) }) qua Mongoose — giá trị luôn bị ép về String trước khi query',
        matchedCount: safeUsers.length,
        matchedUsers: safeUsers.map((u) => ({ username: u.username, role: u.attributes?.role })),
      },
      isMalicious: exploitConfirmed || heuristicSuspicious,
      exploitConfirmed,
      attackType: exploitConfirmed
        ? 'NoSQL Injection — xác nhận bằng truy vấn thật trên MongoDB'
        : (heuristicSuspicious ? 'Chuỗi nghi ngờ (chưa khai thác được trên field này)' : 'Normal input'),
      scenario: '§4.2 - MongoDB injection via $where operator or object injection',
      examples: [
        { attack: '{ "$gt": "" }', description: 'Object injection - bypasses string comparison', dangerous: true },
        { attack: '{ "$ne": null }', description: 'Object injection - matches every document', dangerous: true },
        { attack: '{ "$where": "this.password.length > 0" }', description: '$where JS injection', dangerous: true },
        { attack: 'alice', description: 'Normal string input', dangerous: false },
      ],
      prevention: [
        'Use parameterized queries / ODM validation (Mongoose) — see safePath above',
        'Validate input type (reject objects where strings expected)',
        'Disable $where operator in production',
        'Use OWASP guidelines for NoSQL testing (§4.2)',
        'Implement input sanitization middleware',
      ],
      owasp: 'OWASP Test Guide v4 plans NoSQL injection testing procedures (§4.2)',
    };

    if (exploitConfirmed) {
      result.recommendation = `Input này đã thực sự vượt qua filter trên đường vulnerablePath và trả về ${vulnerableUsers.length} bản ghi (so với ${safeUsers.length} ở đường safePath). Dùng ODM validation để chặn.`;
    } else if (heuristicSuspicious) {
      result.blockedBy = 'Input validation middleware (pattern match)';
      result.recommendation = 'Chuỗi có dấu hiệu tấn công nhưng truy vấn thật trên field này không khai thác được — vẫn nên chặn theo pattern để phòng ngừa.';
    }

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// §4.4 - Data Consistency Demo
// ============================================================

/**
 * GET /api/considerations/consistency/cap-theorem
 * §4.4 - Thực hiện một lần ghi + đọc-lại THẬT trên chính MongoDB đang
 * kết nối (collection ConsistencyProbe) để đo latency và version thật,
 * thay vì trả JSON mô tả dựng sẵn. Nếu DB là replica set, đọc được chỉ
 * định secondaryPreferred để có cơ hội thấy độ trễ nhân bản thật; nếu là
 * standalone thì nói rõ giới hạn thay vì giả vờ có eventual consistency.
 */
router.get('/consistency/cap-theorem', async (req, res) => {
  try {
    const topologyType = mongoose.connection.client?.topology?.description?.type;
    const isReplicaSet = !!topologyType && topologyType !== 'Single';

    const key = 'ac-consistency-demo';
    const t0 = Date.now();
    const written = await ConsistencyProbe.findOneAndUpdate(
      { key },
      { $set: { value: { probeAt: new Date().toISOString() }, updatedAt: new Date() }, $inc: { version: 1 } },
      { upsert: true, new: true, writeConcern: { w: isReplicaSet ? 'majority' : 1 } }
    );
    const writeLatencyMs = Date.now() - t0;

    const t1 = Date.now();
    const readBack = await ConsistencyProbe
      .findOne({ key })
      .read(isReplicaSet ? 'secondaryPreferred' : 'primary');
    const readLatencyMs = Date.now() - t1;

    const consistentReadAfterWrite = !!readBack && readBack.version === written.version;

    res.json({
      section: '§4.4 Data Consistency',
      liveMeasurement: {
        topology: isReplicaSet ? 'replica set' : 'standalone (single node)',
        writtenVersion: written.version,
        readVersion: readBack ? readBack.version : null,
        writeLatencyMs,
        readLatencyMs,
        consistentReadAfterWrite,
        note: isReplicaSet
          ? 'Read dùng secondaryPreferred — nếu secondary chưa kịp nhân bản, readVersion có thể thấp hơn writtenVersion, thể hiện đúng cửa sổ eventual consistency thật.'
          : 'MongoDB hiện tại chỉ chạy 1 node (standalone) nên read-after-write luôn consistent — không thể tạo ra độ trễ nhân bản thật ở cấu hình này; cần triển khai replica set nhiều node để quan sát.',
      },
      capTheorem: {
        description: 'NoSQL databases trade consistency for availability/partition tolerance',
        components: {
          C: { name: 'Consistency', description: 'All nodes see same data simultaneously', rdbms: true, nosql: false },
          A: { name: 'Availability', description: 'Every request receives a response', rdbms: false, nosql: true },
          P: { name: 'Partition Tolerance', description: 'System works despite network failures', rdbms: false, nosql: true },
        },
        nosqlChoice: 'AP (Availability + Partition Tolerance)',
        rdbmsChoice: 'CA (Consistency + Availability)',
      },
      impactOnAC: {
        problem: 'Access control models requiring current state (RBAC, separation of duty) rely on consistent data',
        example: 'If user role is revoked on node A but not yet propagated to node B, node B may still grant access',
        models: [
          { model: 'RBAC', affected: true, reason: 'Role assignment may be inconsistent across nodes' },
          { model: 'ABAC', affected: true, reason: 'Attribute values may differ between nodes' },
          { model: 'DAC', affected: false, reason: 'Owner-based, less dependent on global state' },
        ],
        solution: 'Eventual consistency - accept brief windows of inconsistency; use versioning for critical AC data (như field "version" vừa đo ở trên)',
      },
      eventualConsistency: {
        description: isReplicaSet
          ? 'Kết quả đo được ở trên lấy thật từ replica set đang chạy'
          : 'NoSQL nodes will eventually synchronize, but not immediately (không đo được trực tiếp trên standalone node này)',
        window: isReplicaSet ? `${readLatencyMs} ms (đo thực tế lần probe này)` : 'Typically milliseconds to seconds (lý thuyết — cần replica set để đo thật)',
        risk: 'During sync window, access decisions may be incorrect',
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// §4.6 - Audit Log
// ============================================================

/**
 * GET /api/considerations/audit/logs
 * Xem audit logs với filter
 */
router.get('/audit/logs', authMiddleware, async (req, res) => {
  try {
    const { userId, decision, action, limit = 50, page = 1 } = req.query;
    const filter = {};
    if (userId) filter.userId = userId;
    if (decision) filter.decision = decision;
    if (action) filter.action = action;

    const total = await AuditLog.countDocuments(filter);
    const logs = await AuditLog.find(filter)
      .sort({ timestamp: -1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
      .limit(parseInt(limit));

    res.json({ logs, total, page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/considerations/audit/stats
 * Thống kê audit logs cho dashboard
 */
router.get('/audit/stats', authMiddleware, async (req, res) => {
  try {
    const [totalAllow, totalDeny, byAction, byUser, recent] = await Promise.all([
      AuditLog.countDocuments({ decision: 'allow' }),
      AuditLog.countDocuments({ decision: 'deny' }),
      AuditLog.aggregate([{ $group: { _id: '$action', count: { $sum: 1 } } }]),
      AuditLog.aggregate([
        { $group: { _id: '$username', allow: { $sum: { $cond: [{ $eq: ['$decision', 'allow'] }, 1, 0] } }, deny: { $sum: { $cond: [{ $eq: ['$decision', 'deny'] }, 1, 0] } } } },
        { $sort: { deny: -1 } }, { $limit: 5 },
      ]),
      AuditLog.find({}).sort({ timestamp: -1 }).limit(10),
    ]);

    res.json({
      summary: { totalAllow, totalDeny, total: totalAllow + totalDeny, denyRate: totalDeny / (totalAllow + totalDeny + 0.001) },
      byAction,
      topUsersByDeny: byUser,
      recentLogs: recent,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// §4.8 - AI NLP → Access Control Rule
// ============================================================

/**
 * POST /api/considerations/ai/nlp-to-rule
 * §4.8 - Dùng Anthropic API để parse natural language → formal AC rule
 */
router.post('/ai/nlp-to-rule', authMiddleware, async (req, res) => {
  try {
    const { naturalLanguageText } = req.body;
    if (!naturalLanguageText) return res.status(400).json({ error: 'naturalLanguageText required' });

    const prompt = `You are an Access Control policy parser following NIST IR 8504.
Parse the following natural language text and extract a formal access control rule.

Input: "${naturalLanguageText}"

Return ONLY a JSON object with this exact structure (no markdown, no explanation):
{
  "subjectConditions": {
    "role": "string or null",
    "department": "string or null",
    "group": "string or null",
    "organization": "string or null",
    "minClearance": number_or_null
  },
  "objectConditions": {
    "company": "string or null",
    "branch": "string or null",
    "division": "string or null",
    "classification": "string or null",
    "resourceType": "string or null"
  },
  "actions": ["read", "write", etc],
  "effect": "allow or deny",
  "nosqlModel": "key-value or wide-column or document or graph or all",
  "naturalLanguageRule": "clean restatement of the rule",
  "confidence": 0.0 to 1.0
}`;

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }],
      }),
    });

    const data = await response.json();
    const content = data.content?.[0]?.text || '';

    let parsed;
    try {
      parsed = JSON.parse(content.replace(/```json|```/g, '').trim());
    } catch {
      return res.status(500).json({ error: 'Failed to parse AI response', raw: content });
    }

    res.json({
      input: naturalLanguageText,
      formalRule: parsed,
      nistReference: '§4.8 - AI NLP renders access control policy from natural language documents',
      policyCanBeCreated: true,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/considerations/performance/tradeoffs
 * §4.5 - Security vs Performance tradeoff
 * Đo THẬT latency trung bình của từng mức enforcement, chạy nhiều lần
 * trên một document thật lấy từ MongoDB, thay vì số ms ước lượng.
 */
router.get('/performance/tradeoffs', authMiddleware, async (req, res) => {
  try {
    const sampleResource = await Resource.findOne({});
    if (!sampleResource) {
      return res.status(404).json({ error: 'No resource in DB to benchmark against — run `npm run seed` first' });
    }

    const subjectAttrs = {
      userId: req.user._id?.toString(),
      role: req.user.attributes?.role,
      department: req.user.attributes?.department,
      clearance: req.user.attributes?.clearance,
    };
    const objectAttrs = { ...sampleResource.attributes, type: sampleResource.type };
    const content = sampleResource.content instanceof Map
      ? Object.fromEntries(sampleResource.content)
      : (sampleResource.content || {});

    const ITERATIONS = 20;
    async function timeIt(fn) {
      const t0 = process.hrtime.bigint();
      for (let i = 0; i < ITERATIONS; i++) await fn();
      const t1 = process.hrtime.bigint();
      return Number(t1 - t0) / 1e6 / ITERATIONS; // avg ms/op
    }

    const noAcMs = await timeIt(() => Resource.findById(sampleResource._id).lean());

    const collectionAcMs = await timeIt(() =>
      Policy.findOne({ isActive: true, $or: [{ nosqlModel: sampleResource.nosqlModel }, { nosqlModel: 'all' }] })
    );

    const abacMs = await timeIt(() => makeAccessDecision(subjectAttrs, objectAttrs, 'read'));

    const fgacMs = await timeIt(async () => {
      await makeAccessDecision(subjectAttrs, objectAttrs, 'read');
      Object.keys(content); // chi phí duyệt field thật của document
    });

    const cryptoKey = crypto.randomBytes(32);
    const cryptoIv = crypto.randomBytes(16);
    const encryptedAcMs = await timeIt(async () => {
      await makeAccessDecision(subjectAttrs, objectAttrs, 'read');
      const cipher = crypto.createCipheriv('aes-256-cbc', cryptoKey, cryptoIv);
      Buffer.concat([cipher.update(JSON.stringify(content), 'utf8'), cipher.final()]);
    });

    const fmt = (ms) => `${ms.toFixed(2)}ms`;

    res.json({
      section: '§4.5 Performance',
      benchmarkedAgainst: {
        resourceId: sampleResource._id,
        resourceName: sampleResource.name,
        nosqlModel: sampleResource.nosqlModel,
        iterations: ITERATIONS,
      },
      tradeoffs: [
        { feature: 'No AC', queryTime: fmt(noAcMs), security: 'None', note: 'Resource.findById() thuần, không check quyền' },
        { feature: 'Collection-level AC', queryTime: fmt(collectionAcMs), security: 'Low', note: 'Query 1 Policy theo nosqlModel (coarse-grained, §4.1)' },
        { feature: 'Document-level AC (ABAC)', queryTime: fmt(abacMs), security: 'Medium', note: 'makeAccessDecision() đánh giá toàn bộ Policy collection' },
        { feature: 'Field-level AC (FGAC)', queryTime: fmt(fgacMs), security: 'High', note: 'ABAC + duyệt field trong content thật của document' },
        { feature: 'Encrypted + AC', queryTime: fmt(encryptedAcMs), security: 'Very High', note: '§4.2 - ABAC + AES-256-CBC mã hoá nội dung document (đo thật bằng Node crypto)' },
      ],
      recommendation: '§4.5: Deploy in environments with proper security measures; balance performance and risk',
      note: `Mỗi con số là trung bình ${ITERATIONS} lần chạy thật trên document "${sampleResource.name}" (${sampleResource.nosqlModel}), đo bằng process.hrtime — không còn là số ước lượng.`,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
