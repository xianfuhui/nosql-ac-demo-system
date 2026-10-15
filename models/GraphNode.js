const mongoose = require("mongoose");
const { Schema } = mongoose;

/**
 * Node của mô hình đồ thị (Graph Model) — bài báo §3.2.3, Fig. 9.
 *
 * Khác với key-value/wide-column/document (quan hệ cây phân cấp, §3.1 Fig.5),
 * graph model biểu diễn thuộc tính subject/object bằng MỘT ĐỒ THỊ CÓ HƯỚNG
 * gồm node và edge, không bắt buộc theo cấu trúc cây (Fig. 6).
 *
 * key: định danh duy nhất dạng "loại:mã" (vd "user:sv_an", "resource:diem_svAn")
 * kind: loại node (user | group | course | resource)
 * refId: tham chiếu (tùy chọn) tới document thật trong collection gốc
 */
const GraphNodeSchema = new Schema({
  key: { type: String, required: true, unique: true },
  kind: { type: String, enum: ["user", "group", "course", "resource"], required: true },
  label: { type: String, required: true },
  refId: { type: Schema.Types.ObjectId, default: null },
});

module.exports = mongoose.model("GraphNode", GraphNodeSchema);
