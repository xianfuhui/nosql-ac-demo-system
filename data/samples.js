// Dữ liệu mẫu cho 4 kiểu NoSQL (Nạp dữ liệu → Dữ liệu mẫu)
const SAMPLES = {
  keyvalue: { session: { 'sess:1': 'alice', 'sess:2': 'bob' }, cache: { 'page:home': '<html>', 'user:1:token': 'abc123' } },
  wide: { profile: { r1: { name: 'An', dept: 'HR', salary: 900 }, r2: { name: 'Binh', dept: 'IT', salary: 1200 } }, logs: { r1: { ip: '10.0.0.1', ts: '2024-05-01' } } },
  document: { users: [{ name: 'An', email: 'an@x.com', role: 'hr' }, { name: 'Binh', salary: 1200, role: 'dev' }], orders: [{ id: 1, total: 50, card: '4111' }] },
  graph: { nodes: [{ id: 'x', label: 'user x' }, { id: 'y', label: 'group y' }, { id: 'z', label: 'company z' }, { id: 'f', label: 'file f' }, { id: 'd', label: 'department d' }, { id: 'o', label: 'organization o' }],
    edges: [{ from: 'x', to: 'y', label: 'in' }, { from: 'y', to: 'z', label: 'works for' }, { from: 'f', to: 'd', label: 'managed by' }, { from: 'd', to: 'o', label: 'belongs to' }, { from: 'y', to: 'f', label: 'can read' }] }
};

module.exports = { SAMPLES };
