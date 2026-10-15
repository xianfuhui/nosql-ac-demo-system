const express = require("express");
const router = express.Router();
const { requireRole } = require("../middleware/auth");
const { SCENARIOS } = require("../utils/demoScenarios");

router.use(requireRole("admin"));

// Chức năng #18 Quản lý và thực thi kịch bản demo
router.get("/", async (req, res) => {
  res.render("demo/index", { title: "Kịch bản Demo", active: "demo", scenarios: SCENARIOS, results: {} });
});

router.post("/run/:id", async (req, res) => {
  const scenario = SCENARIOS.find((s) => s.id === req.params.id);
  if (!scenario || !scenario.run) return res.redirect("/demo");

  let result;
  try {
    result = await scenario.run();
  } catch (err) {
    result = {
      input: "—",
      steps: [],
      expected: "—",
      actual: "Lỗi khi chạy kịch bản: " + err.message,
      pass: false,
    };
  }

  const results = {};
  results[scenario.id] = result;
  res.render("demo/index", { title: "Kịch bản Demo", active: "demo", scenarios: SCENARIOS, results, justRan: scenario.id });
});

router.post("/run-all", async (req, res) => {
  const results = {};
  for (const scenario of SCENARIOS) {
    if (!scenario.run) continue;
    try {
      results[scenario.id] = await scenario.run();
    } catch (err) {
      results[scenario.id] = { input: "—", steps: [], expected: "—", actual: "Lỗi: " + err.message, pass: false };
    }
  }
  res.render("demo/index", { title: "Kịch bản Demo", active: "demo", scenarios: SCENARIOS, results, justRan: "all" });
});

module.exports = router;
