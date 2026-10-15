const mongoose = require("mongoose");
const { Schema } = mongoose;

/** Tài liệu học tập gắn với môn học / lớp học. */
const TaiLieuSchema = new Schema(
  {
    tenTaiLieu: { type: String, required: true },
    moTa: { type: String, default: "" },
    monHocId: { type: Schema.Types.ObjectId, ref: "MonHoc", required: true },
    lopHocId: { type: Schema.Types.ObjectId, ref: "LopHoc", default: null },
    // Demo: lưu nội dung dạng text thay vì upload file thật
    noiDung: { type: String, default: "" },
    nguoiTaiLen: { type: Schema.Types.ObjectId, ref: "User", required: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("TaiLieu", TaiLieuSchema);
