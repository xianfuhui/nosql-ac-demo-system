const mongoose = require("mongoose");
const { Schema } = mongoose;

/**
 * Nhật ký hoạt động hệ thống (bài báo §4.6 - Audit).
 * Ghi lại mọi thao tác quan trọng: đăng nhập, truy cập tài nguyên,
 * sửa điểm, quản lý tài khoản... kèm kết quả cho phép/từ chối.
 */
const LogSchema = new Schema(
  {
    thoiGian: { type: Date, default: Date.now },
    nguoiDungId: { type: Schema.Types.ObjectId, ref: "User", default: null },
    tenDangNhap: { type: String, default: "ẩn danh" },
    vaiTro: { type: String, default: null },
    hanhDong: { type: String, required: true }, // vd: 'login', 'read_grade', 'update_grade'
    doiTuong: { type: String, default: "" }, // mô tả đối tượng bị tác động
    ketQua: {
      type: String,
      enum: ["allow", "deny", "success", "fail", "info"],
      required: true,
    },
    chiTiet: { type: String, default: "" },
    kichBanDemo: { type: String, default: null }, // đánh dấu log sinh ra từ kịch bản demo nào
  },
  { timestamps: false }
);

LogSchema.index({ thoiGian: -1 });

module.exports = mongoose.model("Log", LogSchema);
