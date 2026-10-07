require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');
const Resource = require('../models/Resource');
const Policy = require('../models/Policy');
const { GraphNode, GraphEdge } = require('../models/GraphNode');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/nosql_ac_demo';

async function seed() {
  await mongoose.connect(MONGODB_URI);
  console.log('✅ Connected to MongoDB');

  // Clear existing data
  await Promise.all([
    User.deleteMany({}),
    Resource.deleteMany({}),
    Policy.deleteMany({}),
    GraphNode.deleteMany({}),
    GraphEdge.deleteMany({}),
  ]);
  console.log('🗑️  Cleared existing data');

  // ---- USERS (§3.2 - Subject attributes) ----
  const users = await User.create([
    {
      username: 'admin',
      email: 'admin@company.com',
      password: 'admin123',
      attributes: { role: 'admin', department: 'IT', group: 'admins', organization: 'TechCorp', clearance: 5 },
      roles: ['admin', 'manager'],
    },
    {
      username: 'alice',
      email: 'alice@company.com',
      password: 'alice123',
      attributes: { role: 'manager', department: 'Engineering', group: 'dev-team', organization: 'TechCorp', clearance: 3 },
      roles: ['manager'],
    },
    {
      username: 'bob',
      email: 'bob@company.com',
      password: 'bob123',
      attributes: { role: 'employee', department: 'Engineering', group: 'dev-team', organization: 'TechCorp', clearance: 2 },
      roles: ['employee'],
    },
    {
      username: 'carol',
      email: 'carol@finance.com',
      password: 'carol123',
      attributes: { role: 'employee', department: 'Finance', group: 'finance-team', organization: 'TechCorp', clearance: 2 },
      roles: ['employee'],
    },
    {
      username: 'guest_user',
      email: 'guest@external.com',
      password: 'guest123',
      attributes: { role: 'guest', department: 'external', group: 'guests', organization: 'External', clearance: 0 },
      roles: ['guest'],
    },
  ]);
  console.log(`👥 Created ${users.length} users`);

  // ---- RESOURCES (§3.2 - Object attributes, 4 NoSQL models) ----
  const resources = await Resource.create([
    // Key-Value model resources (§2.1.1)
    {
      name: 'session:user123', type: 'record', nosqlModel: 'key-value',
      description: 'User session data (cached)',
      attributes: { company: 'TechCorp', branch: 'main', sensitivity: 1, classification: 'internal' },
      content: { userId: 'user123', token: 'abc...', expires: '2024-12-31' },
    },
    {
      name: 'cache:product-list', type: 'record', nosqlModel: 'key-value',
      description: 'Product list cache',
      attributes: { company: 'TechCorp', branch: 'sales', sensitivity: 1, classification: 'public' },
      content: { products: ['laptop', 'phone'], cached_at: '2024-01-01' },
    },
    // Wide-Column model resources (§2.1.2)
    {
      name: 'employees:engineering', type: 'table', nosqlModel: 'wide-column',
      description: 'Engineering department employee records (column family)',
      attributes: { company: 'TechCorp', branch: 'HQ', division: 'Engineering', department: 'dev-team', sensitivity: 3, classification: 'confidential' },
      content: { columns: ['emp_id', 'name', 'salary', 'performance'] },
    },
    {
      name: 'iot:sensor-data', type: 'table', nosqlModel: 'wide-column',
      description: 'IoT sensor readings (wide-column)',
      attributes: { company: 'TechCorp', branch: 'factory', division: 'Operations', sensitivity: 2, classification: 'internal' },
      content: { columns: ['sensor_id', 'timestamp', 'temperature', 'humidity'] },
    },
    // Document model resources (§2.1.3)
    {
      name: 'product-catalog', type: 'collection', nosqlModel: 'document',
      description: 'Product catalog collection',
      attributes: { company: 'TechCorp', branch: 'sales', division: 'Commerce', sensitivity: 1, classification: 'public' },
      content: { schema: { name: 'string', price: 'number', description: 'string', images: 'array' } },
    },
    {
      name: 'financial-reports', type: 'document', nosqlModel: 'document',
      description: 'Quarterly financial reports (confidential)',
      attributes: { company: 'TechCorp', branch: 'HQ', division: 'Finance', department: 'finance-team', sensitivity: 5, classification: 'secret' },
      content: { fields: ['revenue', 'expenses', 'profit', 'forecast'] },
    },
    {
      name: 'customer-profiles', type: 'collection', nosqlModel: 'document',
      description: 'Customer personal information',
      attributes: { company: 'TechCorp', branch: 'CRM', division: 'Sales', sensitivity: 4, classification: 'confidential' },
      content: { fields: ['name', 'email', 'address', 'purchase_history'] },
    },
    // Graph model resources (§2.1.4)
    {
      name: 'knowledge-graph', type: 'collection', nosqlModel: 'graph',
      description: 'Company knowledge graph (IAM relationships)',
      attributes: { company: 'TechCorp', branch: 'IAM', division: 'IT', sensitivity: 3, classification: 'confidential' },
      content: { nodes: 'users,roles,resources', edges: 'relationships,permissions' },
    },
  ]);
  console.log(`📦 Created ${resources.length} resources`);

  // ---- POLICIES (§3 - AC rules theo từng model) ----
  const policies = await Policy.create([
    // ABAC policies
    {
      name: 'Admin full access',
      description: '§3.3 - Admin role has access to everything',
      policyType: 'ABAC', nosqlModel: 'all', effect: 'allow', priority: 100,
      subjectConditions: { role: 'admin' },
      objectConditions: {},
      actions: ['read', 'write', 'update', 'delete', 'admin'],
      naturalLanguageRule: 'Admin users can perform any action on any resource',
    },
    {
      name: 'Engineering read own department',
      description: '§3.2.2 - Wide-column model: department-level access',
      policyType: 'ABAC', nosqlModel: 'wide-column', effect: 'allow', priority: 50,
      subjectConditions: { department: 'Engineering' },
      objectConditions: { division: 'Engineering', classification: 'confidential' },
      actions: ['read'],
      naturalLanguageRule: 'Engineering employees can read Engineering department records',
    },
    {
      name: 'Public resources - any user',
      description: '§3.2.1 - Key-value: public data accessible by all',
      policyType: 'ABAC', nosqlModel: 'all', effect: 'allow', priority: 10,
      subjectConditions: {},
      objectConditions: { classification: 'public' },
      actions: ['read'],
      naturalLanguageRule: 'Any user can read public resources',
    },
    {
      name: 'Deny guest access to internal',
      description: '§4.2 - Security: guests cannot access internal resources',
      policyType: 'ABAC', nosqlModel: 'all', effect: 'deny', priority: 80,
      subjectConditions: { role: 'guest' },
      objectConditions: { classification: 'internal' },
      actions: ['read', 'write', 'update', 'delete'],
      naturalLanguageRule: 'Guest users cannot access internal or confidential resources',
    },
    {
      name: 'Finance team reads financial data',
      description: '§3.2.2 - Document model: finance department access',
      policyType: 'ABAC', nosqlModel: 'document', effect: 'allow', priority: 60,
      subjectConditions: { department: 'Finance', minClearance: 2 },
      objectConditions: { division: 'Finance' },
      actions: ['read'],
      naturalLanguageRule: 'Finance employees with clearance >= 2 can read Finance division documents',
    },
    {
      name: 'Manager write access',
      description: '§3.3 - RBAC: manager role can write',
      policyType: 'RBAC', nosqlModel: 'all', effect: 'allow', priority: 70,
      subjectConditions: { role: 'manager' },
      objectConditions: { maxSensitivity: 4 },
      actions: ['read', 'write', 'update'],
      naturalLanguageRule: 'Managers can read, write, and update resources with sensitivity <= 4',
    },
    {
      name: 'Deny low clearance secret data',
      description: '§4.2 - MAC: clearance-based access control',
      policyType: 'MAC', nosqlModel: 'all', effect: 'deny', priority: 90,
      subjectConditions: { minClearance: 0 },
      objectConditions: { classification: 'secret' },
      actions: ['read', 'write', 'update', 'delete'],
      naturalLanguageRule: 'Users with clearance < 4 cannot access secret resources',
    },
  ]);

  // Fix: clearance policy logic
  await Policy.findOneAndUpdate(
    { name: 'Deny low clearance secret data' },
    { subjectConditions: { minClearance: 4 } }
  );
  console.log(`📋 Created ${policies.length} policies`);

  // ---- GRAPH NODES + EDGES (§3.2.3 - Fig.9, Fig.10) ----
  await GraphNode.create([
    // Subject nodes
    { nodeId: 'user:alice', label: 'user', name: 'Alice', nodeType: 'subject', data: { department: 'Engineering' } },
    { nodeId: 'user:bob', label: 'user', name: 'Bob', nodeType: 'subject', data: { department: 'Engineering' } },
    { nodeId: 'user:carol', label: 'user', name: 'Carol', nodeType: 'subject', data: { department: 'Finance' } },
    // Attribute nodes
    { nodeId: 'group:dev-team', label: 'group', name: 'Dev Team', nodeType: 'attribute' },
    { nodeId: 'group:finance-team', label: 'group', name: 'Finance Team', nodeType: 'attribute' },
    { nodeId: 'company:techcorp', label: 'company', name: 'TechCorp', nodeType: 'attribute' },
    { nodeId: 'dept:engineering', label: 'department', name: 'Engineering Dept', nodeType: 'attribute' },
    { nodeId: 'dept:finance', label: 'department', name: 'Finance Dept', nodeType: 'attribute' },
    { nodeId: 'org:techcorp-hq', label: 'organization', name: 'TechCorp HQ', nodeType: 'attribute' },
    // Object nodes
    { nodeId: 'file:report-q4', label: 'file', name: 'Q4 Report.pdf', nodeType: 'object', data: { classification: 'confidential' } },
    { nodeId: 'file:source-code', label: 'file', name: 'source_code.zip', nodeType: 'object', data: { classification: 'internal' } },
    { nodeId: 'file:financial-data', label: 'file', name: 'financial_data.xlsx', nodeType: 'object', data: { classification: 'secret' } },
    { nodeId: 'collection:customers', label: 'collection', name: 'Customers DB', nodeType: 'object', data: { classification: 'confidential' } },
  ]);

  await GraphEdge.create([
    // Attribute edges (§3.2.3 - "in", "works for", "belongs to")
    { edgeId: 'e1', fromNodeId: 'user:alice', toNodeId: 'group:dev-team', relationship: 'in', edgeType: 'attribute' },
    { edgeId: 'e2', fromNodeId: 'user:alice', toNodeId: 'company:techcorp', relationship: 'works_for', edgeType: 'attribute' },
    { edgeId: 'e3', fromNodeId: 'user:bob', toNodeId: 'group:dev-team', relationship: 'in', edgeType: 'attribute' },
    { edgeId: 'e4', fromNodeId: 'user:bob', toNodeId: 'company:techcorp', relationship: 'works_for', edgeType: 'attribute' },
    { edgeId: 'e5', fromNodeId: 'user:carol', toNodeId: 'group:finance-team', relationship: 'in', edgeType: 'attribute' },
    { edgeId: 'e6', fromNodeId: 'user:carol', toNodeId: 'company:techcorp', relationship: 'works_for', edgeType: 'attribute' },
    { edgeId: 'e7', fromNodeId: 'group:dev-team', toNodeId: 'dept:engineering', relationship: 'belongs_to', edgeType: 'attribute' },
    { edgeId: 'e8', fromNodeId: 'group:finance-team', toNodeId: 'dept:finance', relationship: 'belongs_to', edgeType: 'attribute' },
    { edgeId: 'e9', fromNodeId: 'dept:engineering', toNodeId: 'org:techcorp-hq', relationship: 'part_of', edgeType: 'attribute' },
    { edgeId: 'e10', fromNodeId: 'file:report-q4', toNodeId: 'dept:engineering', relationship: 'managed_by', edgeType: 'attribute' },
    { edgeId: 'e11', fromNodeId: 'file:source-code', toNodeId: 'dept:engineering', relationship: 'managed_by', edgeType: 'attribute' },
    { edgeId: 'e12', fromNodeId: 'file:financial-data', toNodeId: 'dept:finance', relationship: 'managed_by', edgeType: 'attribute' },
    // Action edges (§3.2.3 Fig.10 - embedded AC rules)
    { edgeId: 'ac1', fromNodeId: 'user:alice', toNodeId: 'file:report-q4', relationship: 'can_read', edgeType: 'action', isACRule: true, data: { description: 'Alice can read Q4 report' } },
    { edgeId: 'ac2', fromNodeId: 'user:alice', toNodeId: 'file:source-code', relationship: 'can_read', edgeType: 'action', isACRule: true, data: { description: 'Alice can read source code' } },
    { edgeId: 'ac3', fromNodeId: 'user:alice', toNodeId: 'file:source-code', relationship: 'can_write', edgeType: 'action', isACRule: true, data: { description: 'Alice (manager) can write source code' } },
    { edgeId: 'ac4', fromNodeId: 'user:bob', toNodeId: 'file:source-code', relationship: 'can_read', edgeType: 'action', isACRule: true, data: { description: 'Bob can read source code' } },
    { edgeId: 'ac5', fromNodeId: 'user:carol', toNodeId: 'file:financial-data', relationship: 'can_read', edgeType: 'action', isACRule: true, data: { description: 'Carol can read financial data' } },
    { edgeId: 'ac6', fromNodeId: 'group:dev-team', toNodeId: 'collection:customers', relationship: 'can_read', edgeType: 'action', isACRule: true, data: { description: 'Dev team can read customer data' } },
  ]);
  console.log('🕸️  Created graph nodes and edges');

  console.log('\n✅ Seed complete!\n');
  console.log('📝 Test accounts:');
  console.log('   admin / admin123   (role: admin, clearance: 5)');
  console.log('   alice / alice123   (role: manager, dept: Engineering)');
  console.log('   bob   / bob123     (role: employee, dept: Engineering)');
  console.log('   carol / carol123   (role: employee, dept: Finance)');
  console.log('   guest_user / guest123  (role: guest, clearance: 0)');

  await mongoose.disconnect();
  process.exit(0);
}

seed().catch(err => {
  console.error('❌ Seed failed:', err);
  process.exit(1);
});
