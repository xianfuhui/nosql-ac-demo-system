require("dotenv").config();
const express = require("express");
const session = require("express-session");
const methodOverride = require("method-override");
const path = require("path");

const { connectDB } = require("./config/db");
const { attachLocals } = require("./middleware/auth");
const { mongoSanitize } = require("./middleware/sanitize");

const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride("_method"));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev_secret",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 4 }, // 4 giờ
  })
);

// Chống NoSQL Injection cho mọi request (bài báo §4.2)
app.use(mongoSanitize);
app.use(attachLocals);

// ===== Routes =====
app.use("/", require("./routes/auth"));
app.use("/", require("./routes/dashboard"));
app.use("/accounts", require("./routes/accounts"));
app.use("/courses", require("./routes/courses"));
app.use("/classes", require("./routes/classes"));
app.use("/students", require("./routes/students"));
app.use("/grades", require("./routes/grades"));
app.use("/documents", require("./routes/documents"));
app.use("/search", require("./routes/search"));
app.use("/logs", require("./routes/logs"));
app.use("/policies", require("./routes/policies"));
app.use("/ai", require("./routes/ai"));
app.use("/demo", require("./routes/demo"));

app.use((req, res) => {
  res.status(404).render("error-404");
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render("error-500", { error: err.message });
});

const PORT = process.env.PORT || 3000;

const User = require("./models/User");
const { seedData } = require("./seed/seedData");

connectDB()
  .then(async (info) => {
    app.locals.dbInfo = info;

    // CSDL in-memory chỉ tồn tại trong vòng đời process này -> luôn seed lại.
    // CSDL thật mà đang trống (lần đầu chạy) -> tự seed cho tiện, không ghi đè nếu đã có dữ liệu.
    const userCount = await User.countDocuments();
    if (info.mode === "memory" || userCount === 0) {
      console.log("[Seed] Đang tạo dữ liệu mẫu tự động...");
      await seedData();
    }

    app.listen(PORT, () => {
      console.log(`\n=== Hệ thống quản lý giáo dục (NIST IR 8504 demo) ===`);
      console.log(`Server đang chạy tại: http://localhost:${PORT}`);
      console.log(`Chế độ CSDL: ${info.mode === "real" ? "MongoDB thật" : "MongoDB in-memory (demo)"}`);
      console.log(`Đăng nhập demo: admin1 / gv_toan / gv_van / sv_an / sv_binh / sv_chau — mật khẩu: 123456\n`);
    });
  })
  .catch((err) => {
    console.error("Không thể khởi động do lỗi kết nối CSDL:", err);
    process.exit(1);
  });
