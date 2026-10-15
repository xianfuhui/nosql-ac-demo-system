require("dotenv").config();
const { connectDB, closeDB } = require("../config/db");
const { seedData } = require("./seedData");

(async () => {
  try {
    await connectDB();
    await seedData();
    console.log("Hoàn tất. Đóng kết nối...");
    await closeDB();
    process.exit(0);
  } catch (err) {
    console.error("Lỗi khi seed dữ liệu:", err);
    process.exit(1);
  }
})();
