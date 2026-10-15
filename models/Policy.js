const mongoose = require("mongoose");
const { Schema } = mongoose;

/**
 * Quy tắc phân quyền (Access Control Policy) - mô hình ABAC dạng đồ thị
 * theo bài báo §3.2.3 (Fig. 9, Fig. 10): một policy là một "đường đi"
 *   subject attribute (node) --edge--> action --edge--> object attribute (node)
 * được lưu trực tiếp dưới dạng tài liệu NoSQL (không cần ngoại khóa),
 * thể hiện đúng tinh thần "embed access control policy" của graph NoSQL.
 *
 * subjectAttr / objectAttr là các điều kiện thuộc tính (attribute-based),
 * so khớp linh hoạt thay vì gắn cứng vào một subject/object cụ thể -
 * đúng như mô tả "any users in group x can read objects that belong to
 * division h" trong bài báo (§3.2.2).
 */
const PolicySchema = new Schema(
  {
    ten: { type: String, required: true },
    moTa: { type: String, default: "" },

    // Thuộc tính của chủ thể (subject attribute node trong Fig. 9)
    subjectAttr: {
      role: { type: String, default: null }, // admin | giangvien | sinhvien | null = bất kỳ
      khoa: { type: String, default: null },
      scope: {
        type: String,
        enum: ["any", "own", "assigned"],
        default: "any",
        // any: không giới hạn thêm theo quan hệ sở hữu/phân công
        // own: chỉ chính chủ thể (vd sinh viên chỉ xem điểm của mình)
        // assigned: chỉ tài nguyên được phân công (vd giảng viên với lớp mình dạy)
      },
    },

    // Hành động (edge "can read" / "can write" trong Fig. 10)
    action: {
      type: String,
      enum: ["read", "create", "update", "delete"],
      required: true,
    },

    // Thuộc tính của đối tượng (object attribute node trong Fig. 9)
    objectAttr: {
      resourceType: {
        type: String,
        enum: [
          "user",
          "monhoc",
          "lophoc",
          "diem",
          "tailieu",
          "log",
          "policy",
        ],
        required: true,
      },
      khoa: { type: String, default: null },
    },

    effect: { type: String, enum: ["allow", "deny"], default: "allow" },
    priority: { type: Number, default: 10 }, // số nhỏ hơn ưu tiên hơn khi xung đột
    active: { type: Boolean, default: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Policy", PolicySchema);
