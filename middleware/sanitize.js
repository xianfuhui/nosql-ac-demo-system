/**
 * Chống NoSQL Injection (bài báo §4.2 - Security).
 *
 * Bài báo cảnh báo: toán tử như "$where" có thể nhận mã JavaScript tùy ý,
 * và kẻ tấn công có thể lợi dụng các toán tử truy vấn Mongo ($gt, $ne, $regex...)
 * được "tiêm" qua input (vd gửi { "$ne": null } thay vì một chuỗi mật khẩu)
 * để vượt qua điều kiện so khớp.
 *
 * Middleware này đệ quy loại bỏ mọi key bắt đầu bằng "$" hoặc chứa "."
 * trong req.body, req.query, req.params trước khi dữ liệu được dùng để
 * xây truy vấn Mongoose - đây là biện pháp phòng thủ tiêu chuẩn.
 */
function sanitizeValue(value, onBlocked) {
  if (Array.isArray(value)) {
    return value.map((v) => sanitizeValue(v, onBlocked));
  }
  if (value && typeof value === "object") {
    const clean = {};
    for (const key of Object.keys(value)) {
      if (key.startsWith("$") || key.includes(".")) {
        onBlocked(key);
        continue; // loại bỏ key nguy hiểm
      }
      clean[key] = sanitizeValue(value[key], onBlocked);
    }
    return clean;
  }
  return value;
}

function mongoSanitize(req, res, next) {
  req.blockedInjectionKeys = [];
  const onBlocked = (key) => req.blockedInjectionKeys.push(key);

  if (req.body) req.body = sanitizeValue(req.body, onBlocked);
  if (req.query) {
    const cleaned = sanitizeValue(req.query, onBlocked);
    // req.query trong Express 4 là getter trên object gốc; ghi đè từng key
    for (const k of Object.keys(req.query)) delete req.query[k];
    Object.assign(req.query, cleaned);
  }
  if (req.params) req.params = sanitizeValue(req.params, onBlocked);

  next();
}

module.exports = { mongoSanitize };
