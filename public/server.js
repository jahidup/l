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

// ========== JWT SECRET ==========
const JWT_SECRET = 'null_protocol_super_secret_2025';

// ========== SQLite Database Setup ==========
const db = new sqlite3.Database('./database.sqlite');

db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    credits INTEGER DEFAULT 10,
    is_blocked INTEGER DEFAULT 0,
    is_admin INTEGER DEFAULT 0,
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

  // Insert default admin if not exists
  const adminPass = bcrypt.hashSync('admin123', 10);
  db.run(`INSERT OR IGNORE INTO users (username, password, credits, is_admin, created_at)
          VALUES (?, ?, 999999, 1, datetime('now'))`, ['admin', adminPass]);
});

// ========== Helper: Verify Token ==========
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

// ========== USER LOGIN ==========
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.is_blocked) return res.status(403).json({ error: 'Account blocked' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, JWT_SECRET);
    res.json({ token, username: user.username, credits: user.credits, is_admin: user.is_admin });
  });
});

// ========== SEARCH API (deducts credit) ==========
app.post('/api/search', verifyToken, async (req, res) => {
  const { apiType, query } = req.body;
  const userId = req.user.id;

  // Check credits
  db.get(`SELECT credits, is_blocked FROM users WHERE id = ?`, [userId], async (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    if (user.is_blocked) return res.status(403).json({ error: 'Account blocked' });
    if (user.credits < 1) return res.status(402).json({ error: 'Insufficient credits' });

    // Deduct credit
    db.run(`UPDATE users SET credits = credits - 1 WHERE id = ?`, [userId]);

    // Call external API (use same endpoints as before)
    const apiConfig = getApiConfig(apiType, query);
    let result = {};
    try {
      const response = await axios.get(apiConfig.url, { timeout: 15000 });
      result = response.data;
    } catch (error) {
      result = { error: 'API failed', message: error.message };
    }

    // Log search
    db.run(`INSERT INTO search_logs (user_id, api_type, query, timestamp, response) VALUES (?, ?, ?, datetime('now'), ?)`,
      [userId, apiType, query, JSON.stringify(result)]);

    res.json({ success: true, credits_left: user.credits - 1, data: result });
  });
});

function getApiConfig(type, query) {
  const endpoints = {
    phone: `https://ayaanmods.site/number.php?key=annonymous&number=${encodeURIComponent(query)}`,
    aadhaar: `https://users-xinfo-admin.vercel.app/api?key=7demo&type=aadhar&term=${encodeURIComponent(query)}`,
    vehicle: `https://vehicle-info-aco-api.vercel.app/info?vehicle=${encodeURIComponent(query)}`,
    ifsc: `https://ab-ifscinfoapi.vercel.app/info?ifsc=${encodeURIComponent(query)}`,
    email: `https://abbas-apis.vercel.app/api/email?mail=${encodeURIComponent(query)}`,
    pincode: `https://api.postalpincode.in/pincode/${encodeURIComponent(query)}`,
    gst: `https://api.b77bf911.workers.dev/gst?number=${encodeURIComponent(query)}`,
    ip_info: `https://abbas-apis.vercel.app/api/ip?ip=${encodeURIComponent(query)}`,
    ff_info: `https://abbas-apis.vercel.app/api/ff-info?uid=${encodeURIComponent(query)}`,
    // add others similarly
  };
  return { url: endpoints[type] || endpoints.phone };
}

// ========== ADMIN APIs (require admin token) ==========
function verifyAdmin(req, res, next) {
  verifyToken(req, res, () => {
    if (!req.user.is_admin) return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

app.get('/admin/users', verifyAdmin, (req, res) => {
  db.all(`SELECT id, username, credits, is_blocked, is_admin, created_at FROM users`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/admin/user', verifyAdmin, (req, res) => {
  const { username, password, credits, is_blocked, is_admin } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const hashed = bcrypt.hashSync(password, 10);
  db.run(`INSERT INTO users (username, password, credits, is_blocked, is_admin, created_at)
          VALUES (?, ?, ?, ?, ?, datetime('now'))`,
    [username, hashed, credits || 10, is_blocked ? 1 : 0, is_admin ? 1 : 0], function(err) {
      if (err) return res.status(400).json({ error: 'Username already exists' });
      res.json({ success: true, id: this.lastID });
    });
});

app.put('/admin/user/:id', verifyAdmin, (req, res) => {
  const { credits, is_blocked } = req.body;
  const id = req.params.id;
  db.run(`UPDATE users SET credits = ?, is_blocked = ? WHERE id = ?`, [credits, is_blocked ? 1 : 0, id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.delete('/admin/user/:id', verifyAdmin, (req, res) => {
  db.run(`DELETE FROM users WHERE id = ? AND is_admin = 0`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ========== Serve frontend ==========
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
