const mongoose = require("mongoose");
const { Schema } = mongoose;

/** Điểm của sinh viên trong 1 lớp học phần. */
const DiemSchema = new Schema(
  {
    sinhVienId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    lopHocId: { type: Schema.Types.ObjectId, ref: "LopHoc", required: true },
    monHocId: { type: Schema.Types.ObjectId, ref: "MonHoc", required: true },
    diemChuyenCan: { type: Number, default: null, min: 0, max: 10 },
    diemGiuaKy: { type: Number, default: null, min: 0, max: 10 },
    diemCuoiKy: { type: Number, default: null, min: 0, max: 10 },
    diemTongKet: { type: Number, default: null, min: 0, max: 10 },
    capNhatBoi: { type: Schema.Types.ObjectId, ref: "User", default: null },
  },
  { timestamps: true }
);

DiemSchema.index({ sinhVienId: 1, lopHocId: 1 }, { unique: true });

module.exports = mongoose.model("Diem", DiemSchema);
