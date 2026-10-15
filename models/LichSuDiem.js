const mongoose = require("mongoose");
const { Schema } = mongoose;

/**
 * Lịch sử chỉnh sửa điểm (bài báo §4.6 - Audit).
 * Ghi lại ai sửa, sửa gì, lúc nào, giá trị cũ/mới.
 */
const LichSuDiemSchema = new Schema(
  {
    diemId: { type: Schema.Types.ObjectId, ref: "Diem", required: true },
    sinhVienId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    lopHocId: { type: Schema.Types.ObjectId, ref: "LopHoc", required: true },
    truong: { type: String, required: true }, // tên trường điểm bị sửa
    giaTriCu: { type: Schema.Types.Mixed, default: null },
    giaTriMoi: { type: Schema.Types.Mixed, default: null },
    nguoiSua: { type: Schema.Types.ObjectId, ref: "User", required: true },
    thoiGian: { type: Date, default: Date.now },
  },
  { timestamps: false }
);

module.exports = mongoose.model("LichSuDiem", LichSuDiemSchema);
