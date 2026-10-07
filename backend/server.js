require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const connectDB = require('./config/database');

const app = express();

// Connect MongoDB
connectDB();

// Middleware
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(morgan('dev'));

// ---- Routes theo từng section bài báo ----
app.use('/api/auth',           require('./routes/auth'));           // §4.2 Auth
app.use('/api/policies',       require('./routes/policies'));       // §3   Policy Builder
app.use('/api/nosql-types',    require('./routes/nosqlTypes'));     // §2   NoSQL Types Explorer
app.use('/api/graph',          require('./routes/graph'));          // §3.2.3 Graph AC
app.use('/api/considerations', require('./routes/considerations')); // §4 Considerations

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'NoSQL Access Control Demo - NIST IR 8504',
    timestamp: new Date().toISOString(),
    sections: {
      '§2': 'GET /api/nosql-types/overview',
      '§3': 'GET/POST /api/policies',
      '§3.2.3': 'GET /api/graph/full',
      '§4.1': 'POST /api/considerations/fgac/demo',
      '§4.2': 'POST /api/considerations/security/injection-demo',
      '§4.4': 'GET /api/considerations/consistency/cap-theorem',
      '§4.6': 'GET /api/considerations/audit/logs',
      '§4.8': 'POST /api/considerations/ai/nlp-to-rule',
    },
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`\n🚀 NoSQL AC Demo Server running on http://localhost:${PORT}`);
  console.log(`📖 API docs: http://localhost:${PORT}/api/health\n`);
});
