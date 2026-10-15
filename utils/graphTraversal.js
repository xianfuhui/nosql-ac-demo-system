/**
 * Duyệt đồ thị thật trên collection "graphedges" — minh họa cơ chế graph
 * model của bài báo (§3.2.3): "the graph model does not have limitations on
 * the number of edges and nodes connected in a sequence of relationships...
 * allows access to data at the finest possible granularity."
 *
 * Khác với utils/accessControl.js (tra một collection "policies" riêng,
 * kiểu Document model §3.2.2), hàm ở đây duyệt trực tiếp trên các edge đã
 * lưu sẵn trong chính đồ thị dữ liệu — đúng tinh thần Fig. 10: luật phân
 * quyền được nhúng thẳng vào DB dưới dạng cạnh, không cần kho policy riêng.
 */
const GraphEdge = require("../models/GraphEdge");
const GraphNode = require("../models/GraphNode");

/** Lấy toàn bộ cạnh xuất phát từ 1 node — dùng để vẽ "vùng lân cận" thật của node đó. */
async function neighborhood(nodeKey) {
  const outgoing = await GraphEdge.find({ from: nodeKey }).lean();
  const incoming = await GraphEdge.find({ to: nodeKey }).lean();
  return { outgoing, incoming };
}

/**
 * BFS thật trên collection graphedges để tìm xem có tồn tại một "chuỗi cạnh"
 * (sequence of links, đúng từ bài báo dùng) nối từ `fromKey` tới `toKey`
 * mà cạnh cuối cùng trong chuỗi có type = permissionEdgeType hay không.
 * Trả về đường đi thật (danh sách các document edge) nếu tìm thấy.
 */
async function traversePermission(fromKey, permissionEdgeType, toKey, maxHops = 4) {
  // Bước 1: BFS theo các cạnh QUAN HỆ (không phải permission) để từ fromKey
  // gom mọi node có thể đi tới được (vd user -> nhóm -> môn...).
  let frontier = [fromKey];
  const visited = new Map(); // nodeKey -> cạnh dẫn tới nó
  visited.set(fromKey, null);
  let hops = 0;

  while (frontier.length > 0 && hops < maxHops) {
    const edges = await GraphEdge.find({ from: { $in: frontier }, type: { $ne: permissionEdgeType } }).lean();
    const nextFrontier = [];
    for (const e of edges) {
      if (!visited.has(e.to)) {
        visited.set(e.to, e);
        nextFrontier.push(e.to);
      }
    }
    frontier = nextFrontier;
    hops++;
  }

  // Bước 2: từ MỌI node đã gom được (kể cả fromKey), kiểm tra có cạnh
  // permission (vd "can_read") đi thẳng tới toKey hay không — đây chính là
  // bước "tìm luật được nhúng sẵn trong đồ thị" theo Fig. 10.
  const reachableKeys = [...visited.keys()];
  const permEdge = await GraphEdge.findOne({ from: { $in: reachableKeys }, type: permissionEdgeType, to: toKey }).lean();

  if (!permEdge) {
    return { found: false, path: [] };
  }

  // Dựng lại chuỗi cạnh thật từ fromKey -> ... -> permEdge.from -> toKey
  const path = [];
  let cur = permEdge.from;
  const chain = [];
  while (cur !== fromKey && visited.get(cur)) {
    const e = visited.get(cur);
    chain.unshift(e);
    cur = e.from;
  }
  path.push(...chain, permEdge);

  return { found: true, path };
}

async function getNode(key) {
  return GraphNode.findOne({ key }).lean();
}

module.exports = { neighborhood, traversePermission, getNode };
