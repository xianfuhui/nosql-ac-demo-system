const express = require('express');
const { GraphNode, GraphEdge } = require('../models/GraphNode');
const { authMiddleware } = require('../middleware/auth');

const router = express.Router();

// GET /api/graph/nodes - lấy tất cả nodes
router.get('/nodes', authMiddleware, async (req, res) => {
  try {
    const { nodeType, label } = req.query;
    const filter = {};
    if (nodeType) filter.nodeType = nodeType;
    if (label) filter.label = label;
    const nodes = await GraphNode.find(filter);
    res.json({ nodes });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/graph/edges - lấy tất cả edges
router.get('/edges', authMiddleware, async (req, res) => {
  try {
    const { fromNodeId, toNodeId, edgeType } = req.query;
    const filter = {};
    if (fromNodeId) filter.fromNodeId = fromNodeId;
    if (toNodeId) filter.toNodeId = toNodeId;
    if (edgeType) filter.edgeType = edgeType;
    const edges = await GraphEdge.find(filter);
    res.json({ edges });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/graph/full - lấy toàn bộ graph (nodes + edges) cho visualization
router.get('/full', authMiddleware, async (req, res) => {
  try {
    const nodes = await GraphNode.find({});
    const edges = await GraphEdge.find({});
    res.json({ nodes, edges });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/graph/nodes - thêm node
router.post('/nodes', authMiddleware, async (req, res) => {
  try {
    const node = await GraphNode.create(req.body);
    res.status(201).json({ node });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/graph/edges - thêm edge
router.post('/edges', authMiddleware, async (req, res) => {
  try {
    const edge = await GraphEdge.create(req.body);
    res.status(201).json({ edge });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/graph/nodes/:nodeId
router.delete('/nodes/:nodeId', authMiddleware, async (req, res) => {
  try {
    await GraphNode.findOneAndDelete({ nodeId: req.params.nodeId });
    await GraphEdge.deleteMany({ $or: [{ fromNodeId: req.params.nodeId }, { toNodeId: req.params.nodeId }] });
    res.json({ message: 'Node and related edges deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/graph/check-access
 * §3.2.3 - Kiểm tra quyền truy cập theo Graph model
 * Tìm đường đi từ subject → object qua các edges
 * Nếu có edge với relationship "can_read/can_write..." → allow
 */
router.post('/check-access', authMiddleware, async (req, res) => {
  try {
    const { subjectNodeId, objectNodeId, action } = req.body;

    // Tìm direct action edge: subject → object với relationship = action
    const directEdge = await GraphEdge.findOne({
      fromNodeId: subjectNodeId,
      toNodeId: objectNodeId,
      relationship: `can_${action}`,
      edgeType: 'action',
    });

    if (directEdge) {
      return res.json({
        decision: 'allow',
        path: [subjectNodeId, objectNodeId],
        edge: directEdge,
        reason: `Direct action edge found: "${directEdge.relationship}"`,
        isEmbeddedACRule: directEdge.isACRule,
      });
    }

    // Tìm path qua intermediate nodes (BFS)
    const visited = new Set([subjectNodeId]);
    const queue = [[subjectNodeId, [subjectNodeId]]];

    while (queue.length > 0) {
      const [currentNodeId, path] = queue.shift();

      const outEdges = await GraphEdge.find({ fromNodeId: currentNodeId });

      for (const edge of outEdges) {
        if (visited.has(edge.toNodeId)) continue;
        visited.add(edge.toNodeId);

        const newPath = [...path, edge.toNodeId];

        // Kiểm tra nếu đây là action edge đến objectNode
        if (edge.toNodeId === objectNodeId && edge.edgeType === 'action' &&
            (edge.relationship === `can_${action}` || edge.relationship === 'can_admin')) {
          return res.json({
            decision: 'allow',
            path: newPath,
            edge,
            reason: `Path found through graph: ${newPath.join(' → ')}`,
            isEmbeddedACRule: edge.isACRule,
          });
        }

        if (newPath.length < 6) { // max depth 5
          queue.push([edge.toNodeId, newPath]);
        }
      }
    }

    res.json({
      decision: 'deny',
      path: [],
      reason: `No path found from "${subjectNodeId}" to "${objectNodeId}" with action "${action}"`,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/graph/embed-ac-rule
 * §3.2.3 Fig.10 - Nhúng AC rule trực tiếp vào graph dưới dạng action edge
 * "user x (node) in (edge) group y (node) can read (edge) file y (node)"
 */
router.post('/embed-ac-rule', authMiddleware, async (req, res) => {
  try {
    const { fromNodeId, toNodeId, action, description } = req.body;

    const edge = await GraphEdge.create({
      edgeId: `ac_${fromNodeId}_${action}_${toNodeId}_${Date.now()}`,
      fromNodeId,
      toNodeId,
      relationship: `can_${action}`,
      edgeType: 'action',
      isACRule: true,
      data: { description, createdBy: req.user.username, createdAt: new Date() },
    });

    res.status(201).json({
      edge,
      message: `AC rule embedded: "${fromNodeId}" can ${action} "${toNodeId}"`,
      naturalLanguage: `Node "${fromNodeId}" can ${action} node "${toNodeId}" (embedded rule in graph)`,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
