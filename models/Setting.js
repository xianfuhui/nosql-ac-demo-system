const mongoose = require("mongoose");
const { Schema } = mongoose;

/** Cấu hình hệ thống lưu trong DB (vd API key nhập qua giao diện Admin). */
const SettingSchema = new Schema({
  key: { type: String, required: true, unique: true },
  value: { type: String, default: "" },
});

module.exports = mongoose.model("Setting", SettingSchema);
