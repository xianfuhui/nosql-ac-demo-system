/**
 * Phiên bản hàm thuần (không phải middleware Express) của logic chống
 * NoSQL Injection trong middleware/sanitize.js — dùng để minh họa trực
 * tiếp trong trang Kịch bản Demo (kịch bản #5) mà không cần dựng request giả.
 */
function mongoSanitize(value, blockedKeysOut) {
  if (Array.isArray(value)) {
    return value.map((v) => mongoSanitize(v, blockedKeysOut));
  }
  if (value && typeof value === "object") {
    const clean = {};
    for (const key of Object.keys(value)) {
      if (key.startsWith("$") || key.includes(".")) {
        blockedKeysOut.push(key);
        continue;
      }
      clean[key] = mongoSanitize(value[key], blockedKeysOut);
    }
    return clean;
  }
  return value;
}

module.exports = { mongoSanitize };
