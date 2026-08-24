const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// ---- Config ----
// Set this to your actual Google review link, e.g.
// https://search.google.com/local/writereview?placeid=YOUR_PLACE_ID
const GOOGLE_REVIEW_URL = process.env.GOOGLE_REVIEW_URL || 'https://g.page/r/REPLACE_ME/review';
const ADMIN_KEY = process.env.ADMIN_KEY || 'changeme'; // simple shared-secret for admin routes
const PORT = process.env.PORT || 3000;

// ---- DB setup ----
const db = new Database(path.join(__dirname, 'data.sqlite'));
db.exec(`
  CREATE TABLE IF NOT EXISTS cards (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    ua TEXT,
    ip_hash TEXT,
    FOREIGN KEY (card_id) REFERENCES cards(id)
  );
`);

function requireAdmin(req, res, next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

function hashIp(ip) {
  // lightweight non-reversible-ish hash, good enough for rough dedup, not for PII storage
  let h = 0;
  for (let i = 0; i < ip.length; i++) {
    h = (h << 5) - h + ip.charCodeAt(i);
    h |= 0;
  }
  return String(h);
}

// ---- Public redirect route ----
// This is the URL you put on each physical card / QR code:
//   https://yourdomain.com/r/CARD_ID
app.get('/r/:cardId', (req, res) => {
  const { cardId } = req.params;
  const card = db.prepare('SELECT * FROM cards WHERE id = ?').get(cardId);

  if (!card) {
    return res.redirect(302, GOOGLE_REVIEW_URL);
  }

  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  db.prepare('INSERT INTO scans (card_id, ts, ua, ip_hash) VALUES (?, ?, ?, ?)').run(
    cardId,
    new Date().toISOString(),
    req.headers['user-agent'] || '',
    ip ? hashIp(ip) : ''
  );

  res.redirect(302, GOOGLE_REVIEW_URL);
});

// ---- Admin API (used by the dashboard) ----
app.get('/api/cards', requireAdmin, (req, res) => {
  const cards = db.prepare('SELECT * FROM cards ORDER BY created_at DESC').all();
  const counts = db.prepare(`
    SELECT card_id, COUNT(*) as total FROM scans GROUP BY card_id
  `).all();
  const countMap = Object.fromEntries(counts.map(c => [c.card_id, c.total]));
  res.json(cards.map(c => ({ ...c, totalScans: countMap[c.id] || 0 })));
});

app.post('/api/cards', requireAdmin, (req, res) => {
  const { id, label } = req.body;
  if (!id || !label) return res.status(400).json({ error: 'id and label required' });
  db.prepare('INSERT INTO cards (id, label, created_at) VALUES (?, ?, ?)').run(
    id, label, new Date().toISOString()
  );
  res.json({ ok: true });
});

app.delete('/api/cards/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM scans WHERE card_id = ?').run(req.params.id);
  db.prepare('DELETE FROM cards WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/scans/daily', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT card_id, substr(ts, 1, 10) as date, COUNT(*) as count
    FROM scans
    GROUP BY card_id, date
    ORDER BY date ASC
  `).all();
  res.json(rows);
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Review redirect service running on port ${PORT}`);
  console.log(`Public redirect format: https://your-deployed-domain/r/CARD_ID`);
});
