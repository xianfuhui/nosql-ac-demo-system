const mongoose = require("mongoose");
const { Schema } = mongoose;

/** Lớp học (Class) - gắn với 1 môn học + 1 giảng viên phụ trách + ds sinh viên. */
const LopHocSchema = new Schema(
  {
    maLop: { type: String, required: true, unique: true, trim: true },
    tenLop: { type: String, required: true },
    monHocId: { type: Schema.Types.ObjectId, ref: "MonHoc", required: true },
    giangVienId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    khoa: { type: String, required: true },
    siSoToiDa: { type: Number, default: 60 },
    sinhVienIds: [{ type: Schema.Types.ObjectId, ref: "User" }],
  },
  { timestamps: true }
);

module.exports = mongoose.model("LopHoc", LopHocSchema);
