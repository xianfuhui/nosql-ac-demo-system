const Policy = require('../models/Policy');
const AuditLog = require('../models/AuditLog');

/**
 * §3.3 Access Control Engine
 * Implements ABAC (primary) + RBAC (via role attribute)
 * Theo NIST IR 8504 - evaluates subject + object attributes against policy rules
 */

// Đánh giá một policy rule với subject và object attributes
function evaluatePolicy(policy, subjectAttrs, objectAttrs, action, envAttrs = {}) {
  const sc = policy.subjectConditions || {};
  const oc = policy.objectConditions || {};
  const ec = policy.environmentConditions || {};

  // --- Kiểm tra subject conditions ---
  if (sc.role && sc.role !== subjectAttrs.role) return false;
  if (sc.department && sc.department !== subjectAttrs.department) return false;
  if (sc.group && sc.group !== subjectAttrs.group) return false;
  if (sc.organization && sc.organization !== subjectAttrs.organization) return false;
  if (sc.minClearance != null && subjectAttrs.clearance < sc.minClearance) return false;
  if (sc.userId && sc.userId !== subjectAttrs.userId) return false;

  // RBAC check: nếu policy có role condition, kiểm tra roles array
  if (sc.role && subjectAttrs.roles && subjectAttrs.roles.length > 0) {
    if (!subjectAttrs.roles.includes(sc.role) && sc.role !== subjectAttrs.role) return false;
  }

  // --- Kiểm tra object conditions ---
  if (oc.company && oc.company !== objectAttrs.company) return false;
  if (oc.branch && oc.branch !== objectAttrs.branch) return false;
  if (oc.division && oc.division !== objectAttrs.division) return false;
  if (oc.department && oc.department !== objectAttrs.department) return false;
  if (oc.classification && oc.classification !== objectAttrs.classification) return false;
  if (oc.maxSensitivity != null && objectAttrs.sensitivity > oc.maxSensitivity) return false;
  if (oc.resourceType && oc.resourceType !== objectAttrs.type) return false;

  // --- Kiểm tra action ---
  if (!policy.actions.includes(action) && !policy.actions.includes('admin')) return false;

  // --- Kiểm tra environment conditions (§4.7) ---
  if (ec.timeFrom && ec.timeTo) {
    const now = envAttrs.currentTime || new Date();
    const currentHour = now.getHours();
    const currentMin = now.getMinutes();
    const [fromH, fromM] = ec.timeFrom.split(':').map(Number);
    const [toH, toM] = ec.timeTo.split(':').map(Number);
    const currentMinutes = currentHour * 60 + currentMin;
    const fromMinutes = fromH * 60 + fromM;
    const toMinutes = toH * 60 + toM;
    if (currentMinutes < fromMinutes || currentMinutes > toMinutes) return false;
  }

  return true;
}

/**
 * Core access decision function
 * Returns { decision, matchedPolicy, reason }
 */
async function makeAccessDecision(subjectAttrs, objectAttrs, action, envAttrs = {}) {
  try {
    // Lấy tất cả policies đang active, sắp xếp theo priority giảm dần
    const policies = await Policy.find({ isActive: true }).sort({ priority: -1 });

    let allowPolicy = null;
    let denyPolicy = null;

    for (const policy of policies) {
      const matched = evaluatePolicy(policy, subjectAttrs, objectAttrs, action, envAttrs);
      if (matched) {
        if (policy.effect === 'deny' && !denyPolicy) denyPolicy = policy;
        if (policy.effect === 'allow' && !allowPolicy) allowPolicy = policy;
      }
    }

    // Deny takes priority (deny-overrides)
    if (denyPolicy) {
      return {
        decision: 'deny',
        matchedPolicy: denyPolicy.name,
        matchedPolicyId: denyPolicy._id,
        reason: `Denied by policy: "${denyPolicy.name}"`,
      };
    }

    if (allowPolicy) {
      return {
        decision: 'allow',
        matchedPolicy: allowPolicy.name,
        matchedPolicyId: allowPolicy._id,
        reason: `Allowed by policy: "${allowPolicy.name}"`,
      };
    }

    // Default deny nếu không có policy nào match
    return {
      decision: 'deny',
      matchedPolicy: null,
      matchedPolicyId: null,
      reason: 'No matching policy found (default deny)',
    };
  } catch (err) {
    return { decision: 'deny', reason: 'AC Engine error: ' + err.message };
  }
}

/**
 * Express middleware: kiểm tra quyền truy cập resource
 * Usage: router.get('/resource/:id', acMiddleware('read'), handler)
 */
function acMiddleware(action) {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized: no user context' });
      }

      const subjectAttrs = {
        userId: req.user._id?.toString(),
        role: req.user.attributes?.role,
        department: req.user.attributes?.department,
        group: req.user.attributes?.group,
        organization: req.user.attributes?.organization,
        clearance: req.user.attributes?.clearance,
        roles: req.user.roles || [],
      };

      const objectAttrs = req.resourceAttrs || {};

      const result = await makeAccessDecision(subjectAttrs, objectAttrs, action, {
        ipAddress: req.ip,
        currentTime: new Date(),
      });

      // §4.6 Ghi audit log
      await AuditLog.create({
        userId: req.user._id,
        username: req.user.username,
        action,
        resource: req.path,
        resourceId: req.params.id,
        decision: result.decision,
        matchedPolicy: result.matchedPolicy,
        matchedPolicyId: result.matchedPolicyId,
        subjectAttributes: subjectAttrs,
        objectAttributes: objectAttrs,
        reason: result.reason,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      if (result.decision === 'deny') {
        return res.status(403).json({
          error: 'Access Denied',
          reason: result.reason,
          decision: result.decision,
        });
      }

      req.acDecision = result;
      next();
    } catch (err) {
      next(err);
    }
  };
}

module.exports = { acMiddleware, makeAccessDecision, evaluatePolicy };
