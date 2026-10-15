const express = require("express");
const router = express.Router();
const { requireRole } = require("../middleware/auth");
const { writeLog } = require("../utils/accessControl");
const Setting = require("../models/Setting");
const Policy = require("../models/Policy");

router.use(requireRole("admin"));

// Chức năng #17 AI hỗ trợ tạo quy tắc phân quyền (bài báo §4.8 Support for AI)
// Admin nhập quy định bằng tiếng Việt -> Gemini API phân tích -> đề xuất policy
// (chưa áp dụng ngay) -> Admin xem lại, chọn và xác nhận mới ghi vào DB.

async function getApiKey() {
  const fromDb = await Setting.findOne({ key: "GEMINI_API_KEY" });
  return (fromDb && fromDb.value) || process.env.GEMINI_API_KEY || "";
}

router.get("/", async (req, res) => {
  const apiKey = await getApiKey();
  res.render("admin/ai", {
    title: "AI hỗ trợ tạo quy tắc",
    active: "ai",
    hasKey: !!apiKey,
    keyPreview: apiKey ? apiKey.slice(0, 4) + "••••••••" + apiKey.slice(-4) : "",
    suggestions: req.session.aiSuggestions || null,
    inputText: req.session.aiInputText || "",
    error: null,
  });
});

router.post("/save-key", async (req, res) => {
  const { apiKey } = req.body;
  await Setting.findOneAndUpdate(
    { key: "GEMINI_API_KEY" },
    { value: (apiKey || "").trim() },
    { upsert: true }
  );
  await writeLog(req, req.session.user, "update:ai_key", "allow", "Cập nhật Gemini API key qua giao diện Admin");
  res.redirect("/ai");
});

router.post("/suggest", async (req, res) => {
  const user = req.session.user;
  const apiKey = await getApiKey();
  const text = (req.body.quyDinh || "").trim();
  req.session.aiInputText = text;

  if (!apiKey) {
    await writeLog(req, user, "ai_suggest", "fail", "Chưa cấu hình Gemini API key");
    return res.render("admin/ai", {
      title: "AI hỗ trợ tạo quy tắc",
      active: "ai",
      hasKey: false,
      keyPreview: "",
      suggestions: null,
      inputText: text,
      error: "Chưa cấu hình Gemini API key. Vui lòng nhập API key ở ô phía trên trước.",
    });
  }

  if (!text) {
    return res.redirect("/ai");
  }

  try {
    const suggestions = await callGeminiForPolicies(apiKey, text);
    req.session.aiSuggestions = suggestions;
    await writeLog(req, user, "ai_suggest", "success", `AI đề xuất ${suggestions.length} quy tắc từ văn bản quy định`);
  } catch (err) {
    await writeLog(req, user, "ai_suggest", "fail", "Lỗi gọi Gemini API: " + err.message);
    return res.render("admin/ai", {
      title: "AI hỗ trợ tạo quy tắc",
      active: "ai",
      hasKey: true,
      keyPreview: apiKey.slice(0, 4) + "••••••••" + apiKey.slice(-4),
      suggestions: null,
      inputText: text,
      error: "Lỗi khi gọi Gemini API: " + err.message,
    });
  }

  res.redirect("/ai");
});

router.post("/confirm", async (req, res) => {
  const user = req.session.user;
  const suggestions = req.session.aiSuggestions || [];
  const chosenIdx = [].concat(req.body.chosen || []).map(Number);

  let created = 0;
  for (const i of chosenIdx) {
    const s = suggestions[i];
    if (!s) continue;
    await Policy.create({
      ten: s.ten,
      moTa: (s.moTa || "") + " (tạo tự động từ AI, đã được Admin xác nhận)",
      subjectAttr: s.subjectAttr,
      action: s.action,
      objectAttr: s.objectAttr,
      effect: s.effect || "allow",
      priority: s.priority || 10,
    });
    created++;
  }

  req.session.aiSuggestions = null;
  req.session.aiInputText = null;
  await writeLog(req, user, "ai_confirm", "allow", `Admin xác nhận và tạo ${created} chính sách từ đề xuất AI`);
  res.redirect("/policies");
});

router.post("/discard", (req, res) => {
  req.session.aiSuggestions = null;
  res.redirect("/ai");
});

/**
 * Gọi Gemini API, yêu cầu trả về JSON mô tả các quy tắc ABAC khớp với
 * schema Policy của hệ thống (subjectAttr/action/objectAttr/effect) —
 * minh họa quy trình NLP -> formal access control rule ở bài báo §4.8.
 */
async function callGeminiForPolicies(apiKey, quyDinhText) {
  // Bài báo §4.8 (Support for AI) mô tả cụ thể quy trình NLP->luật hình thức,
  // với ví dụ chuẩn: "employees from the product division have to attend a
  // security training course to work on project X" được dịch thành:
  // "(user attribute = employee from product division) ∧ (operation = work)
  //  ∧ (resource attribute = project X) ∧ (condition = attended security
  //  training) → (permission = grant)".
  // Yêu cầu Gemini trả về CẢ hai: (a) đúng định dạng tuple hình thức này để
  // bám sát bài báo, VÀ (b) ánh xạ sang schema Policy nội bộ để có thể lưu
  // thẳng vào hệ thống sau khi Admin xác nhận.
  const prompt = `Bạn là một AI NLP system theo mô tả ở mục 4.8 "Support for AI" của tài liệu NIST IR 8504
"Access Control on NoSQL Databases". Nhiệm vụ: đọc một đoạn quy định viết bằng tiếng Việt tự nhiên,
nhận diện các câu có thể hình thành luật kiểm soát truy cập, rồi sinh ra luật hình thức.

Bài báo cho ví dụ mẫu: câu "employees from the product division have to attend a security training
course to work on project X" được dịch thành luật hình thức nối bằng các toán tử Boolean:
"(user attribute = employee from product division) ∧ (operation = work) ∧ (resource attribute =
project X) ∧ (condition = attended security training) → (permission = grant)".

Với mỗi câu trong đoạn quy định dưới đây có thể hình thành một luật truy cập, hãy trả về MỘT PHẦN TỬ
JSON với CẢ HAI biểu diễn:
{
  "ten": "tên ngắn gọn cho luật",
  "moTa": "diễn giải bằng tiếng Việt",
  "formalRule": "chuỗi luật hình thức ĐÚNG văn phong bài báo, dạng '(user attribute = ...) ∧ (operation = ...) ∧ (resource attribute = ...) → (permission = allow|deny)', viết bằng tiếng Việt cho các giá trị thuộc tính",
  "subjectAttr": { "role": "admin|giangvien|sinhvien|null", "khoa": "tên khoa hoặc null", "scope": "any|own|assigned" },
  "action": "read|create|update|delete",
  "objectAttr": { "resourceType": "user|monhoc|lophoc|diem|tailieu|log|policy", "khoa": "tên khoa hoặc null" },
  "effect": "allow|deny",
  "priority": 10
}
CHỈ trả về một mảng JSON hợp lệ, không thêm giải thích, không markdown code fence.

Đoạn quy định:
"""${quyDinhText}"""`;

  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${encodeURIComponent(apiKey)}`;
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.2 },
    }),
  });

  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`HTTP ${resp.status} - ${errText.slice(0, 200)}`);
  }
  const data = await resp.json();
  const raw = data?.candidates?.[0]?.content?.parts?.[0]?.text || "[]";
  const cleaned = raw.replace(/```json|```/g, "").trim();

  let parsed;
  try {
    parsed = JSON.parse(cleaned);
  } catch (e) {
    throw new Error("Không phân tích được JSON từ phản hồi AI. Nội dung trả về: " + cleaned.slice(0, 200));
  }
  if (!Array.isArray(parsed)) throw new Error("Phản hồi AI không phải là một mảng quy tắc.");
  return parsed;
}

module.exports = router;
