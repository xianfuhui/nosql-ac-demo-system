const express = require('express');
const Policy = require('../models/Policy');
const { authMiddleware, requireAdmin } = require('../middleware/auth');
const { makeAccessDecision } = require('../middleware/acEngine');

const router = express.Router();

// GET /api/policies - lấy tất cả policies
router.get('/', authMiddleware, async (req, res) => {
  try {
    const { nosqlModel, policyType, isActive } = req.query;
    const filter = {};
    if (nosqlModel) filter.nosqlModel = nosqlModel;
    if (policyType) filter.policyType = policyType;
    if (isActive !== undefined) filter.isActive = isActive === 'true';

    const policies = await Policy.find(filter).sort({ priority: -1, createdAt: -1 });
    res.json({ policies, total: policies.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/policies/:id
router.get('/:id', authMiddleware, async (req, res) => {
  try {
    const policy = await Policy.findById(req.params.id);
    if (!policy) return res.status(404).json({ error: 'Policy not found' });
    res.json({ policy });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/policies - tạo policy mới (ADMIN ONLY)
router.post('/', authMiddleware, requireAdmin, async (req, res) => {
  try {
    const policyData = { ...req.body, createdBy: req.user.username };
    const policy = await Policy.create(policyData);
    res.status(201).json({ policy, message: 'Policy created successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/policies/:id - cập nhật policy (ADMIN ONLY)
router.put('/:id', authMiddleware, requireAdmin, async (req, res) => {
  try {
    const policy = await Policy.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!policy) return res.status(404).json({ error: 'Policy not found' });
    res.json({ policy, message: 'Policy updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/policies/:id (ADMIN ONLY)
router.delete('/:id', authMiddleware, requireAdmin, async (req, res) => {
  try {
    await Policy.findByIdAndDelete(req.params.id);
    res.json({ message: 'Policy deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/policies/evaluate - §3.3
 * Test một access request thủ công với subject + object + action
 * Demo: "ai có thể truy cập gì?"
 */
router.post('/evaluate', authMiddleware, async (req, res) => {
  try {
    const { subjectAttributes, objectAttributes, action } = req.body;

    if (!subjectAttributes || !objectAttributes || !action) {
      return res.status(400).json({ error: 'subjectAttributes, objectAttributes, action required' });
    }

    const result = await makeAccessDecision(subjectAttributes, objectAttributes, action);

    // Lấy thêm chi tiết policy đã match
    let policyDetail = null;
    if (result.matchedPolicyId) {
      policyDetail = await Policy.findById(result.matchedPolicyId);
    }

    res.json({
      ...result,
      policyDetail,
      request: { subjectAttributes, objectAttributes, action },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/policies/generate-natural-language
 * §3.2 - Sinh natural language rule từ policy attributes
 * Ví dụ Fig.7: "user x in group y of department z can read file f managed by branch g of company h"
 */
router.post('/generate-natural-language', authMiddleware, async (req, res) => {
  try {
    const { subjectConditions, objectConditions, actions, effect, nosqlModel } = req.body;
    const sc = subjectConditions || {};
    const oc = objectConditions || {};

    let nlRule = '';

    if (nosqlModel === 'key-value') {
      // §3.2.1 - Key-Value model rule (Fig.7)
      const subject = sc.userId ? `user "${sc.userId}"` : (sc.group ? `users in group "${sc.group}"` : 'any user');
      const subjectContext = [
        sc.group && !sc.userId ? null : sc.group ? `in group "${sc.group}"` : null,
        sc.department ? `of department "${sc.department}"` : null,
      ].filter(Boolean).join(' ');
      const obj = oc.division ? `objects of branch "${oc.branch || '*'}"` : `files`;
      const objContext = [
        oc.branch ? `managed by branch "${oc.branch}"` : null,
        oc.company ? `of company "${oc.company}"` : null,
      ].filter(Boolean).join(' ');
      nlRule = `${subject}${subjectContext ? ' ' + subjectContext : ''} ${effect === 'deny' ? 'cannot' : 'can'} ${actions.join('/')} ${obj}${objContext ? ' ' + objContext : ''}`;
    } else if (nosqlModel === 'wide-column' || nosqlModel === 'document') {
      // §3.2.2 - Wide-Column & Document model rule (Fig.8)
      const subject = sc.userId ? `user "${sc.userId}"` : (sc.group ? `users in group "${sc.group}"` : 'any user');
      nlRule = [
        subject,
        sc.group ? `in group "${sc.group}"` : null,
        sc.department ? `of department "${sc.department}"` : null,
        sc.organization ? `in organization "${sc.organization}"` : null,
        effect === 'deny' ? 'cannot' : 'can',
        actions.join('/'),
        oc.division ? `files managed by division "${oc.division}"` : 'resources',
        oc.branch ? `under branch "${oc.branch}"` : null,
        oc.company ? `in company "${oc.company}"` : null,
      ].filter(Boolean).join(' ');
    } else if (nosqlModel === 'graph') {
      // §3.2.3 - Graph model rule
      nlRule = [
        sc.userId ? `user "${sc.userId}"` : 'any user',
        sc.group ? `(in) group "${sc.group}"` : null,
        sc.organization ? `(works for) organization "${sc.organization}"` : null,
        effect === 'deny' ? 'cannot' : 'can',
        actions.join('/'),
        oc.division ? `file (managed by) department "${oc.division}"` : 'resources',
        oc.company ? `(belongs to) organization "${oc.company}"` : null,
      ].filter(Boolean).join(' ');
    } else {
      nlRule = [
        sc.role ? `${sc.role}s` : 'users',
        sc.department ? `in department "${sc.department}"` : null,
        effect === 'deny' ? 'cannot' : 'can',
        actions.join('/'),
        oc.classification ? `"${oc.classification}" resources` : 'resources',
        oc.company ? `of company "${oc.company}"` : null,
      ].filter(Boolean).join(' ');
    }

    res.json({ naturalLanguageRule: nlRule.trim() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
