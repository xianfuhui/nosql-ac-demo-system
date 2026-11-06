'use strict';
// Phân quyền ABAC theo trường dữ liệu, mô phỏng ý tưởng NIST IR 8504:
// luật = {role, nhóm trường (object attribute), điều kiện}; mặc định từ chối, deny ghi đè permit.

const GROUPS = {
  academic: ['G1', 'G2', 'G3', 'failures', 'absences', 'studytime', 'paid', 'schoolsup', 'higher'],
  personal: ['sex', 'age', 'address', 'reason', 'traveltime', 'activities', 'nursery', 'internet', 'romantic',
             'freetime', 'goout', 'Dalc', 'Walc', 'health'],
  family: ['famsize', 'Pstatus', 'Medu', 'Fedu', 'Mjob', 'Fjob', 'guardian', 'famrel', 'famsup'],
};
const ROLES = ['admin', 'teacher', 'counselor'];

const FIELD_GROUP = {};
for (const [g, fs] of Object.entries(GROUPS)) for (const f of fs) FIELD_GROUP[f] = g;
const groupOf = (col) => FIELD_GROUP[col] || 'other';

const DEFAULT_POLICIES = [
  { _id: 'R1', role: 'teacher', groups: ['academic'], effect: 'permit', cond: 'trained', note: 'Giáo viên đã tập huấn xem điểm học tập' },
  { _id: 'R2', role: 'counselor', groups: ['personal'], effect: 'permit', cond: null, note: 'Tư vấn viên xem thông tin cá nhân' },
  { _id: 'R3', role: 'counselor', groups: ['academic'], effect: 'permit', cond: 'at_risk', note: 'Tư vấn viên xem điểm của học sinh có nguy cơ (G2 < 10)' },
  { _id: 'R4', role: 'admin', groups: ['academic', 'personal', 'family', 'other'], effect: 'permit', cond: null, note: 'Quản trị xem tất cả' },
];

const CONDS = {
  trained: (subject) => !!subject.trained,
  at_risk: (subject, row) => typeof row.G2 === 'number' && row.G2 < 10,
};

function cleanSubject(q = {}) {
  const role = ROLES.includes(q.role) ? q.role : 'teacher';
  const school = String(q.school || '').slice(0, 60);
  return { role, school: school || (role === 'admin' ? '*' : ''), trained: q.trained === 'true' || q.trained === true };
}

// Thuộc tính trường học của subject phải khớp thuộc tính trường học của object
function inScope(subject, row, schoolField) {
  if (!schoolField) return true;
  if (subject.school === '*') return subject.role === 'admin';
  return subject.school !== '' && row[schoolField] === subject.school;
}

function allowedGroups(subject, policies, row) {
  const out = {};
  for (const g of [...Object.keys(GROUPS), 'other']) {
    let permit = false, deny = false;
    for (const p of policies) {
      if (p.role !== subject.role || !p.groups.includes(g)) continue;
      if (p.cond && !(CONDS[p.cond] && CONDS[p.cond](subject, row))) continue;
      if (p.effect === 'deny') deny = true; else if (p.effect === 'permit') permit = true;
    }
    out[g] = permit && !deny;
  }
  return out;
}

// Trả về chỉ các trường được phép, cùng số trường bị khoá
function project(subject, policies, row, columnNames) {
  const allowed = allowedGroups(subject, policies, row);
  const data = {};
  let locked = 0;
  for (const c of columnNames) {
    if (allowed[groupOf(c)]) data[c] = row[c] === undefined ? null : row[c];
    else locked++;
  }
  return { data, locked };
}

module.exports = { GROUPS, ROLES, groupOf, DEFAULT_POLICIES, cleanSubject, inScope, project };
