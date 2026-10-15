/**
 * Kết nối MongoDB.
 * - Ưu tiên dùng MONGODB_URI thật (bài báo §2, §3: dữ liệu lưu trong NoSQL database thật).
 * - Nếu không kết nối được và USE_MEMORY_DB_FALLBACK=true, tự khởi động một
 *   MongoDB in-memory (mongodb-memory-server) để demo không cần cài đặt MongoDB.
 */
const mongoose = require("mongoose");

let memoryServer = null;

async function connectDB() {
  const uri = process.env.MONGODB_URI;
  const useFallback = process.env.USE_MEMORY_DB_FALLBACK !== "false";

  mongoose.set("strictQuery", true);

  // 1) Thử kết nối MongoDB thật trước
  if (uri) {
    try {
      await mongoose.connect(uri, { serverSelectionTimeoutMS: 3000 });
      console.log(`[DB] Đã kết nối MongoDB thật tại: ${uri}`);
      return { mode: "real", uri };
    } catch (err) {
      console.warn(`[DB] Không kết nối được MongoDB thật (${err.message}).`);
      if (!useFallback) throw err;
      console.warn("[DB] Chuyển sang MongoDB in-memory để demo...");
    }
  }

  // 2) Fallback: MongoDB in-memory (chỉ phục vụ demo/chạy thử)
  const { MongoMemoryServer } = require("mongodb-memory-server");
  memoryServer = await MongoMemoryServer.create();
  const memUri = memoryServer.getUri("edu_nosql_ac");
  await mongoose.connect(memUri);
  console.log(`[DB] Đã khởi động MongoDB in-memory tại: ${memUri}`);
  console.log(
    "[DB] LƯU Ý: Đây là CSDL tạm trong bộ nhớ, dữ liệu sẽ mất khi tắt server."
  );
  console.log(
    "[DB] Để dùng MongoDB thật, cài MongoDB rồi đặt MONGODB_URI trong file .env"
  );
  return { mode: "memory", uri: memUri };
}

async function closeDB() {
  await mongoose.disconnect();
  if (memoryServer) await memoryServer.stop();
}

module.exports = { connectDB, closeDB, mongoose };
