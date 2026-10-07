const express = require('express');
const AuditLog = require('../models/AuditLog');
const Resource = require('../models/Resource');
const Policy = require('../models/Policy');
const { authMiddleware } = require('../middleware/auth');
const { makeAccessDecision } = require('../middleware/acEngine');

const router = express.Router();

// ============================================================
// §4.1 - Fine-Grained Access Control Demo
// ============================================================

/**
 * POST /api/considerations/fgac/demo
 * So sánh coarse-grained vs fine-grained access control
 */
router.post('/fgac/demo', authMiddleware, async (req, res) => {
  try {
    const { userId, resourceId, requestedField } = req.body;
    const resource = await Resource.findById(resourceId);
    if (!resource) return res.status(404).json({ error: 'Resource not found' });

    // Coarse-grained: chỉ check ở level collection
    const coarseResult = {
      level: 'collection',
      decision: 'allow', // NoSQL thường chỉ check ở đây
      description: '§4.1: Most NoSQL databases only grant access at collection level',
      example: `User gets access to entire collection "${resource.nosqlModel}" - cannot restrict specific fields`,
    };

    // Fine-grained: check ở level field/document (cần add-on)
    const subjectAttrs = {
      userId: req.user._id?.toString(),
      role: req.user.attributes?.role,
      department: req.user.attributes?.department,
      clearance: req.user.attributes?.clearance,
    };
    const objectAttrs = { ...resource.attributes, type: resource.type };
    const fineResult = await makeAccessDecision(subjectAttrs, objectAttrs, 'read');

    res.json({
      comparison: {
        coarseGrained: coarseResult,
        fineGrained: {
          level: requestedField ? `field: "${requestedField}"` : 'document',
          decision: fineResult.decision,
          matchedPolicy: fineResult.matchedPolicy,
          reason: fineResult.reason,
          description: '§4.1: Fine-grained AC via ABAC policy engine (add-on mechanism)',
          example: requestedField
            ? `User tries to access field "${requestedField}" of resource "${resource.name}"`
            : `User tries to access document "${resource.name}"`,
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
 * Hiển thị các granularity levels theo từng NoSQL model
 */
router.get('/fgac/levels', async (req, res) => {
  res.json({
    granularityLevels: {
      'key-value':  ['database', 'table', 'key', 'value'],
      'wide-column':['database', 'column-family', 'row', 'column-id', 'value'],
      'document':   ['database', 'collection', 'document', 'field', 'value'],
      'graph':      ['database', 'node', 'edge', 'property'],
      'RDBMS':      ['database', 'schema', 'table', 'row', 'column', 'cell'],
    },
    nistFigure: 'Fig. 5 - Hierarchical structure relationships',
    challenge: 'NoSQL enforces AC at collection/family level; cell-level requires add-on (§4.1)',
  });
});

// ============================================================
// §4.2 - Security Demo: Injection Attack Simulation
// ============================================================

/**
 * POST /api/considerations/security/injection-demo
 * Mô phỏng NoSQL injection attack (§4.2)
 * EDUCATIONAL PURPOSE ONLY - không thực sự execute malicious code
 */
router.post('/security/injection-demo', async (req, res) => {
  const { inputUsername } = req.body;

  const isMalicious = typeof inputUsername === 'object' ||
    (typeof inputUsername === 'string' && (
      inputUsername.includes('$') ||
      inputUsername.includes('{') ||
      inputUsername.includes('where') ||
      inputUsername.includes('eval')
    ));

  const result = {
    input: inputUsername,
    isMalicious,
    attackType: isMalicious ? 'NoSQL Injection' : 'Normal input',
    scenario: '§4.2 - MongoDB injection via $where operator or object injection',
    examples: [
      { attack: '{ "$gt": "" }', description: 'Object injection - bypasses string comparison', dangerous: true },
      { attack: '{ "$where": "this.password.length > 0" }', description: '$where JS injection', dangerous: true },
      { attack: 'alice', description: 'Normal string input', dangerous: false },
    ],
    prevention: [
      'Use parameterized queries / ODM validation (Mongoose)',
      'Validate input type (reject objects where strings expected)',
      'Disable $where operator in production',
      'Use OWASP guidelines for NoSQL testing (§4.2)',
      'Implement input sanitization middleware',
    ],
    owasp: 'OWASP Test Guide v4 plans NoSQL injection testing procedures (§4.2)',
  };

  if (isMalicious) {
    result.blockedBy = 'Input validation middleware';
    result.recommendation = 'This input was blocked. Always validate and sanitize NoSQL queries.';
  }

  res.json(result);
});

// ============================================================
// §4.4 - Data Consistency Demo
// ============================================================

/**
 * GET /api/considerations/consistency/cap-theorem
 * Demo CAP theorem trong NoSQL (§4.4)
 */
router.get('/consistency/cap-theorem', async (req, res) => {
  res.json({
    section: '§4.4 Data Consistency',
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
      solution: 'Eventual consistency - accept brief windows of inconsistency; use versioning for critical AC data',
    },
    eventualConsistency: {
      description: 'NoSQL nodes will eventually synchronize, but not immediately',
      window: 'Typically milliseconds to seconds',
      risk: 'During sync window, access decisions may be incorrect',
    },
  });
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
 */
router.get('/performance/tradeoffs', async (req, res) => {
  res.json({
    section: '§4.5 Performance',
    tradeoffs: [
      { feature: 'No AC', queryTime: '~1ms', security: 'None', note: 'Default NoSQL setting' },
      { feature: 'Collection-level AC', queryTime: '~2ms', security: 'Low', note: 'Most common NoSQL implementation' },
      { feature: 'Document-level AC (ABAC)', queryTime: '~5ms', security: 'Medium', note: 'Add-on policy engine' },
      { feature: 'Field-level AC (FGAC)', queryTime: '~15ms', security: 'High', note: 'Requires schema extension' },
      { feature: 'Encrypted + AC', queryTime: '~25ms', security: 'Very High', note: '§4.2 - symmetric key encryption' },
    ],
    recommendation: '§4.5: Deploy in environments with proper security measures; balance performance and risk',
  });
});

module.exports = router;
