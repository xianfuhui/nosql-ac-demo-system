const mongoose = require("mongoose");
const { Schema } = mongoose;

/**
 * User (Subject trong mô hình access control - bài báo §3.2).
 * Thuộc tính subject (vai trò, khoa, lớp, môn phụ trách) được dùng để
 * xây dựng chuỗi quan hệ subject attribute -> object attribute như Fig. 7-9.
 */
const UserSchema = new Schema(
  {
    username: { type: String, required: true, unique: true, trim: true },
    passwordHash: { type: String, required: true },
    hoTen: { type: String, required: true },
    email: { type: String },
    role: {
      type: String,
      enum: ["admin", "giangvien", "sinhvien"],
      required: true,
    },
    khoa: { type: String, default: null }, // department attribute
    // Dành cho sinh viên: lớp đang theo học
    lopId: { type: Schema.Types.ObjectId, ref: "LopHoc", default: null },
    // Dành cho giảng viên: các lớp / môn được phân công (object attribute scope)
    lopPhuTrach: [{ type: Schema.Types.ObjectId, ref: "LopHoc" }],
    monPhuTrach: [{ type: Schema.Types.ObjectId, ref: "MonHoc" }],
    active: { type: Boolean, default: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", UserSchema);
