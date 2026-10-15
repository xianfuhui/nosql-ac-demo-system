const mongoose = require("mongoose");
const { Schema } = mongoose;

/**
 * Môn học (Course). Tương ứng "Column family / Collection" trong mô hình
 * wide-column / document NoSQL (bài báo Fig. 2, Fig. 3).
 */
const MonHocSchema = new Schema(
  {
    maMon: { type: String, required: true, unique: true, trim: true },
    tenMon: { type: String, required: true },
    khoa: { type: String, required: true }, // thuộc khoa nào (object attribute)
    soTinChi: { type: Number, default: 3 },
    giangVienIds: [{ type: Schema.Types.ObjectId, ref: "User" }],
  },
  { timestamps: true }
);

module.exports = mongoose.model("MonHoc", MonHocSchema);
