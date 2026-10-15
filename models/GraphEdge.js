const mongoose = require("mongoose");
const { Schema } = mongoose;

/**
 * Edge (cạnh có hướng) của mô hình đồ thị — bài báo §3.2.3, Fig. 9 và Fig. 10.
 *
 * Bài báo (Fig. 10) chỉ rõ: "Edges in the graph model ... can be used to
 * implement either an attribute OR a permitted action... If implemented as
 * a permitted action, the access control rule can be directly embedded in
 * the database, treating a sequence of links as a rule. There is no need to
 * store the access control rule outside of the database."
 *
 * Vì vậy collection này lưu CẢ HAI loại cạnh trong cùng một đồ thị:
 *  - Cạnh quan hệ thuộc tính (attribute edge): "in", "managed_by", "owned_by"...
 *    → tương ứng chuỗi "user x (node) in (edge) group y (node)" ở Fig. 9.
 *  - Cạnh hành động được phép (permission edge): "can_read", "can_update"...
 *    → chính LUẬT PHÂN QUYỀN được nhúng trực tiếp làm dữ liệu, giống Fig. 10
 *    ("user x -in-> group y -can read-> file y"), KHÔNG tra cứu qua một
 *    collection "policies" riêng như mô hình ABAC ở §3.2.2 (xem utils/accessControl.js).
 */
const GraphEdgeSchema = new Schema({
  from: { type: String, required: true }, // GraphNode.key
  type: { type: String, required: true }, // vd: in, managed_by, owned_by, can_read, can_update
  to: { type: String, required: true }, // GraphNode.key
});

GraphEdgeSchema.index({ from: 1, type: 1, to: 1 }, { unique: true });

module.exports = mongoose.model("GraphEdge", GraphEdgeSchema);
