const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// ========== ADMIN CREDENTIALS (4-field) ==========
const ADMIN_CONFIG = {
  USERNAME: "Shahid_Ansari",
  PASSWORD: "Tracker@3739",
  PIN: "2744",
  SECURITY_KEY: "NULL_PROTOCOL"
};

// ========== JWT SECRET ==========
const JWT_SECRET = 'null_protocol_super_secret_2025';

// ========== SQLite Database Setup ==========
const db = new sqlite3.Database('./database.sqlite');

db.serialize(() => {
  // Users table (normal users only, admin not stored here)
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    credits INTEGER DEFAULT 10,
    is_blocked INTEGER DEFAULT 0,
    created_at TEXT
  )`);

  // Search logs table
  db.run(`CREATE TABLE IF NOT EXISTS search_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    api_type TEXT,
    query TEXT,
    timestamp TEXT,
    response TEXT
  )`);
});

// ========== Helper: Verify Token (for users) ==========
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ========== NORMAL USER LOGIN (2 fields) ==========
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.is_blocked) return res.status(403).json({ error: 'Account blocked. Contact admin.' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username, role: 'user' }, JWT_SECRET);
    res.json({ token, username: user.username, credits: user.credits, role: 'user' });
  });
});

// ========== ADMIN LOGIN (4 fields) ==========
app.post('/api/admin/login', (req, res) => {
  const { username, password, pin, securityKey } = req.body;
  if (username === ADMIN_CONFIG.USERNAME &&
      password === ADMIN_CONFIG.PASSWORD &&
      pin === ADMIN_CONFIG.PIN &&
      securityKey === ADMIN_CONFIG.SECURITY_KEY) {
    const token = jwt.sign({ username: ADMIN_CONFIG.USERNAME, role: 'admin' }, JWT_SECRET);
    res.json({ success: true, token, role: 'admin' });
  } else {
    res.status(401).json({ error: 'Invalid admin credentials' });
  }
});

// ========== GET USER INFO (credits, status) ==========
app.get('/api/me', verifyToken, (req, res) => {
  db.get(`SELECT id, username, credits, is_blocked FROM users WHERE id = ?`, [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    res.json({ credits: user.credits, is_blocked: user.is_blocked });
  });
});

// ========== SEARCH API (deducts credit) ==========
app.post('/api/search', verifyToken, async (req, res) => {
  const { apiType, query } = req.body;
  const userId = req.user.id;

  db.get(`SELECT credits, is_blocked FROM users WHERE id = ?`, [userId], async (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    if (user.is_blocked) return res.status(403).json({ error: 'Account blocked' });
    if (user.credits < 1) return res.status(402).json({ error: 'Insufficient credits. Contact admin.' });

    db.run(`UPDATE users SET credits = credits - 1 WHERE id = ?`, [userId]);

    const apiConfig = getApiConfig(apiType, query);
    let result = {};
    try {
      const response = await axios.get(apiConfig.url, { timeout: 15000 });
      result = response.data;
    } catch (error) {
      result = { error: 'API failed', message: error.message };
    }

    // Add branding
    result.developer = 'Shahid Ansari';
    result.powered_by = 'NULL PROTOCOL';

    db.run(`INSERT INTO search_logs (user_id, api_type, query, timestamp, response) VALUES (?, ?, ?, datetime('now'), ?)`,
      [userId, apiType, query, JSON.stringify(result)]);

    db.get(`SELECT credits FROM users WHERE id = ?`, [userId], (err, updated) => {
      res.json({ success: true, credits_left: updated ? updated.credits : user.credits - 1, data: result });
    });
  });
});

// API endpoints (18 APIs)
function getApiConfig(type, query) {
  const encoded = encodeURIComponent(query);
  const endpoints = {
    phone: `https://ayaanmods.site/number.php?key=annonymous&number=${encoded}`,
    aadhaar: `https://users-xinfo-admin.vercel.app/api?key=7demo&type=aadhar&term=${encoded}`,
    ration: `https://number8899.vercel.app/?type=family&aadhar=${encoded}`,
    vehicle: `https://vehicle-info-aco-api.vercel.app/info?vehicle=${encoded}`,
    vehicle_chalan: `https://api.b77bf911.workers.dev/vehicle?registration=${encoded}`,
    vehicle_pro: `https://users-xinfo-admin.vercel.app/api?key=7demo&type=vehicle&term=${encoded}`,
    ifsc: `https://ab-ifscinfoapi.vercel.app/info?ifsc=${encoded}`,
    email: `https://abbas-apis.vercel.app/api/email?mail=${encoded}`,
    pincode: `https://api.postalpincode.in/pincode/${encoded}`,
    gst: `https://api.b77bf911.workers.dev/gst?number=${encoded}`,
    tg_to_num: `https://rootx-tg-num-multi.satyamrajsingh562.workers.dev/3/${encoded}?key=root`,
    ip_info: `https://abbas-apis.vercel.app/api/ip?ip=${encoded}`,
    ff_info: `https://abbas-apis.vercel.app/api/ff-info?uid=${encoded}`,
    ff_ban: `https://abbas-apis.vercel.app/api/ff-ban?uid=${encoded}`,
    tg_info_pro: `https://tg-to-num-six.vercel.app/?key=rootxsuryansh&q=${encoded}`,
    tg_info: `https://api.b77bf911.workers.dev/telegram?user=${encoded}`,
    insta_info: `https://mkhossain.alwaysdata.net/instanum.php?username=${encoded}`,
    github_info: `https://abbas-apis.vercel.app/api/github?username=${encoded}`
  };
  return { url: endpoints[type] || endpoints.phone };
}

// ========== ADMIN APIs (require admin token) ==========
function verifyAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Get all users
app.get('/admin/users', verifyAdmin, (req, res) => {
  db.all(`SELECT id, username, credits, is_blocked, created_at FROM users`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Create new user
app.post('/admin/user', verifyAdmin, (req, res) => {
  const { username, password, credits, is_blocked } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const hashed = bcrypt.hashSync(password, 10);
  db.run(`INSERT INTO users (username, password, credits, is_blocked, created_at) VALUES (?, ?, ?, ?, datetime('now'))`,
    [username, hashed, credits || 10, is_blocked ? 1 : 0], function(err) {
      if (err) return res.status(400).json({ error: 'Username already exists' });
      res.json({ success: true, id: this.lastID });
    });
});

// Update user (credits, block status)
app.put('/admin/user/:id', verifyAdmin, (req, res) => {
  const { credits, is_blocked } = req.body;
  db.run(`UPDATE users SET credits = ?, is_blocked = ? WHERE id = ?`, [credits, is_blocked ? 1 : 0, req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// Delete user
app.delete('/admin/user/:id', verifyAdmin, (req, res) => {
  db.run(`DELETE FROM users WHERE id = ?`, [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true });
  });
});

// Get search logs for a user
app.get('/admin/logs/:userId', verifyAdmin, (req, res) => {
  db.all(`SELECT id, api_type, query, timestamp FROM search_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 100`,
    [req.params.userId], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
});

// ========== Serve frontend ==========
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
