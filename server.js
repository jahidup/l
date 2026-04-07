const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// ========== ADMIN CREDENTIALS ==========
const ADMIN_CONFIG = {
  USERNAME: "Shahid_Ansari",
  PASSWORD: "Tracker@3739",
  PIN: "2744",
  SECURITY_KEY: "NULL_PROTOCOL"
};
const JWT_SECRET = 'null_protocol_super_secret_2025';

// ========== POSTGRESQL CONNECTION ==========
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Required for Render PostgreSQL
});

// ========== INITIALIZE TABLES ==========
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      credits INTEGER DEFAULT 10,
      is_blocked INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS search_logs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      api_type TEXT,
      query TEXT,
      timestamp TIMESTAMP DEFAULT NOW(),
      response TEXT
    );
    CREATE TABLE IF NOT EXISTS api_configs (
      id SERIAL PRIMARY KEY,
      type TEXT UNIQUE NOT NULL,
      url TEXT NOT NULL,
      description TEXT,
      enabled INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('✅ PostgreSQL tables ready');

  // Insert default APIs if none exist
  const res = await pool.query('SELECT COUNT(*) FROM api_configs');
  if (parseInt(res.rows[0].count) === 0) {
    const defaultApis = [
      { type: 'phone', url: 'https://ayaanmods.site/number.php?key=annonymous&number={query}', description: 'Phone lookup' },
      { type: 'aadhaar', url: 'https://users-xinfo-admin.vercel.app/api?key=7demo&type=aadhar&term={query}', description: 'Aadhaar lookup' },
      { type: 'vehicle', url: 'https://vehicle-info-aco-api.vercel.app/info?vehicle={query}', description: 'Vehicle RC' },
      // Add more as needed
    ];
    for (const api of defaultApis) {
      await pool.query(
        `INSERT INTO api_configs (type, url, description, enabled) VALUES ($1, $2, $3, 1)`,
        [api.type, api.url, api.description]
      );
    }
    console.log('📡 Default APIs inserted');
  }
}
initDb().catch(console.error);

// ========== HELPER ==========
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });
  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ========== USER LOGIN ==========
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user || !bcrypt.compareSync(password, user.password)) 
      return res.status(401).json({ error: 'Invalid credentials' });
    if (user.is_blocked) return res.status(403).json({ error: 'Account blocked' });
    const token = jwt.sign({ id: user.id, username: user.username, role: 'user' }, JWT_SECRET);
    res.json({ token, username: user.username, credits: user.credits, role: 'user' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== ADMIN LOGIN ==========
app.post('/api/admin/login', (req, res) => {
  const { username, password, pin, securityKey } = req.body;
  if (username === ADMIN_CONFIG.USERNAME && password === ADMIN_CONFIG.PASSWORD &&
      pin === ADMIN_CONFIG.PIN && securityKey === ADMIN_CONFIG.SECURITY_KEY) {
    const token = jwt.sign({ username: ADMIN_CONFIG.USERNAME, role: 'admin' }, JWT_SECRET);
    res.json({ success: true, token, role: 'admin' });
  } else {
    res.status(401).json({ error: 'Invalid admin credentials' });
  }
});

// ========== GET USER INFO ==========
app.get('/api/me', verifyToken, async (req, res) => {
  const result = await pool.query('SELECT credits, is_blocked FROM users WHERE id = $1', [req.user.id]);
  if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
  res.json(result.rows[0]);
});

// ========== GET AVAILABLE API TYPES ==========
app.get('/api/api-types', verifyToken, async (req, res) => {
  const result = await pool.query('SELECT type, description FROM api_configs WHERE enabled = 1 ORDER BY type');
  res.json(result.rows);
});

// ========== SEARCH ==========
app.post('/api/search', verifyToken, async (req, res) => {
  const { apiType, query } = req.body;
  const userId = req.user.id;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const userRes = await client.query('SELECT credits, is_blocked FROM users WHERE id = $1 FOR UPDATE', [userId]);
    const user = userRes.rows[0];
    if (!user || user.is_blocked) throw new Error('Account blocked');
    if (user.credits < 1) throw new Error('Insufficient credits');

    const apiRes = await client.query('SELECT url FROM api_configs WHERE type = $1 AND enabled = 1', [apiType]);
    if (apiRes.rows.length === 0) throw new Error('API not found');
    let apiUrl = apiRes.rows[0].url.replace('{query}', encodeURIComponent(query));

    await client.query('UPDATE users SET credits = credits - 1 WHERE id = $1', [userId]);

    let result = {};
    try {
      const response = await axios.get(apiUrl, { timeout: 15000 });
      result = response.data;
    } catch (error) {
      result = { error: 'API failed', message: error.message };
    }
    result.developer = 'Shahid Ansari';
    result.powered_by = 'NULL PROTOCOL';

    await client.query(
      `INSERT INTO search_logs (user_id, api_type, query, response) VALUES ($1, $2, $3, $4)`,
      [userId, apiType, query, JSON.stringify(result)]
    );

    const updated = await client.query('SELECT credits FROM users WHERE id = $1', [userId]);
    await client.query('COMMIT');
    res.json({ success: true, credits_left: updated.rows[0].credits, data: result });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ========== ADMIN APIs (similar to before but using PostgreSQL) ==========
function verifyAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    req.admin = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/admin/stats', verifyAdmin, async (req, res) => {
  const totalUsers = await pool.query('SELECT COUNT(*) FROM users');
  const totalCredits = await pool.query('SELECT SUM(credits) FROM users');
  const totalSearches = await pool.query('SELECT COUNT(*) FROM search_logs');
  res.json({
    totalUsers: parseInt(totalUsers.rows[0].count),
    totalCredits: parseInt(totalCredits.rows[0].sum || 0),
    totalSearches: parseInt(totalSearches.rows[0].count)
  });
});

app.get('/admin/users', verifyAdmin, async (req, res) => {
  const search = req.query.search || '';
  let query = 'SELECT id, username, credits, is_blocked, created_at FROM users';
  let params = [];
  if (search) {
    query += ' WHERE username ILIKE $1';
    params.push(`%${search}%`);
  }
  const result = await pool.query(query, params);
  res.json(result.rows);
});

app.post('/admin/user', verifyAdmin, async (req, res) => {
  const { username, password, credits, is_blocked } = req.body;
  const hashed = bcrypt.hashSync(password, 10);
  try {
    const result = await pool.query(
      `INSERT INTO users (username, password, credits, is_blocked) VALUES ($1, $2, $3, $4) RETURNING id`,
      [username, hashed, credits || 10, is_blocked ? 1 : 0]
    );
    res.json({ success: true, id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ error: 'Username already exists' });
  }
});

app.put('/admin/user/:id', verifyAdmin, async (req, res) => {
  const { credits, is_blocked } = req.body;
  await pool.query('UPDATE users SET credits = $1, is_blocked = $2 WHERE id = $3', [credits, is_blocked ? 1 : 0, req.params.id]);
  res.json({ success: true });
});

app.post('/admin/bulk-credits', verifyAdmin, async (req, res) => {
  const { amount } = req.body;
  await pool.query('UPDATE users SET credits = credits + $1', [amount]);
  res.json({ success: true });
});

app.delete('/admin/user/:id', verifyAdmin, async (req, res) => {
  const result = await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' });
  res.json({ success: true });
});

app.get('/admin/logs', verifyAdmin, async (req, res) => {
  const userId = req.query.userId;
  let query = `
    SELECT l.id, l.user_id, u.username, l.api_type, l.query, l.timestamp, l.response
    FROM search_logs l
    LEFT JOIN users u ON l.user_id = u.id
  `;
  let params = [];
  if (userId) {
    query += ' WHERE l.user_id = $1';
    params.push(userId);
  }
  query += ' ORDER BY l.timestamp DESC LIMIT 200';
  const result = await pool.query(query, params);
  res.json(result.rows);
});

app.get('/admin/api-configs', verifyAdmin, async (req, res) => {
  const result = await pool.query('SELECT * FROM api_configs ORDER BY type');
  res.json(result.rows);
});

app.post('/admin/api-configs', verifyAdmin, async (req, res) => {
  const { type, url, description, enabled } = req.body;
  try {
    await pool.query(
      `INSERT INTO api_configs (type, url, description, enabled) VALUES ($1, $2, $3, $4)`,
      [type, url, description || '', enabled ? 1 : 0]
    );
    res.json({ success: true });
  } catch {
    res.status(400).json({ error: 'API type already exists' });
  }
});

app.put('/admin/api-configs/:id', verifyAdmin, async (req, res) => {
  const { type, url, description, enabled } = req.body;
  await pool.query(
    `UPDATE api_configs SET type = $1, url = $2, description = $3, enabled = $4 WHERE id = $5`,
    [type, url, description || '', enabled ? 1 : 0, req.params.id]
  );
  res.json({ success: true });
});

app.delete('/admin/api-configs/:id', verifyAdmin, async (req, res) => {
  await pool.query('DELETE FROM api_configs WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

app.post('/admin/test-api', verifyAdmin, async (req, res) => {
  const { url, query } = req.body;
  const testUrl = url.replace('{query}', encodeURIComponent(query || 'test'));
  try {
    const response = await axios.get(testUrl, { timeout: 10000 });
    res.json({ success: true, data: response.data });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
