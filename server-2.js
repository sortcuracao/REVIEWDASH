const express = require('express');
const cors = require('cors');
const { createClient } = require('@libsql/client');

const app = express();
app.use(cors());
app.use(express.json());

// ---- Config ----
const GOOGLE_REVIEW_URL = process.env.GOOGLE_REVIEW_URL || 'https://g.page/r/REPLACE_ME/review';
const ADMIN_KEY = process.env.ADMIN_KEY || 'changeme';
const PORT = process.env.PORT || 3000;

// Turso connection — set these in Render's Environment tab
const TURSO_URL = process.env.TURSO_DATABASE_URL;
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN;

if (!TURSO_URL || !TURSO_TOKEN) {
  console.error('Missing TURSO_DATABASE_URL or TURSO_AUTH_TOKEN environment variables.');
}

const db = createClient({
  url: TURSO_URL,
  authToken: TURSO_TOKEN
});

// ---- DB setup ----
async function initDb() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS cards (
      id TEXT PRIMARY KEY,
      label TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      card_id TEXT NOT NULL,
      ts TEXT NOT NULL,
      ua TEXT,
      ip_hash TEXT
    )
  `);
}

function requireAdmin(req, res, next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

function hashIp(ip) {
  let h = 0;
  for (let i = 0; i < ip.length; i++) {
    h = (h << 5) - h + ip.charCodeAt(i);
    h |= 0;
  }
  return String(h);
}

// ---- Public redirect route ----
app.get('/r/:cardId', async (req, res) => {
  const { cardId } = req.params;
  try {
    const cardResult = await db.execute({
      sql: 'SELECT * FROM cards WHERE id = ?',
      args: [cardId]
    });

    if (cardResult.rows.length === 0) {
      return res.redirect(302, GOOGLE_REVIEW_URL);
    }

    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    await db.execute({
      sql: 'INSERT INTO scans (card_id, ts, ua, ip_hash) VALUES (?, ?, ?, ?)',
      args: [cardId, new Date().toISOString(), req.headers['user-agent'] || '', ip ? hashIp(ip) : '']
    });

    res.redirect(302, GOOGLE_REVIEW_URL);
  } catch (err) {
    console.error('Redirect error:', err);
    res.redirect(302, GOOGLE_REVIEW_URL);
  }
});

// ---- Admin API ----
app.get('/api/cards', requireAdmin, async (req, res) => {
  try {
    const cardsResult = await db.execute('SELECT * FROM cards ORDER BY created_at DESC');
    const countsResult = await db.execute('SELECT card_id, COUNT(*) as total FROM scans GROUP BY card_id');
    const countMap = Object.fromEntries(countsResult.rows.map(r => [r.card_id, Number(r.total)]));
    const cards = cardsResult.rows.map(c => ({ ...c, totalScans: countMap[c.id] || 0 }));
    res.json(cards);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

app.post('/api/cards', requireAdmin, async (req, res) => {
  const { id, label } = req.body;
  if (!id || !label) return res.status(400).json({ error: 'id and label required' });
  try {
    await db.execute({
      sql: 'INSERT INTO cards (id, label, created_at) VALUES (?, ?, ?)',
      args: [id, label, new Date().toISOString()]
    });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

app.delete('/api/cards/:id', requireAdmin, async (req, res) => {
  try {
    await db.execute({ sql: 'DELETE FROM scans WHERE card_id = ?', args: [req.params.id] });
    await db.execute({ sql: 'DELETE FROM cards WHERE id = ?', args: [req.params.id] });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

app.get('/api/scans/daily', requireAdmin, async (req, res) => {
  try {
    const result = await db.execute(`
      SELECT card_id, substr(ts, 1, 10) as date, COUNT(*) as count
      FROM scans
      GROUP BY card_id, date
      ORDER BY date ASC
    `);
    res.json(result.rows.map(r => ({ ...r, count: Number(r.count) })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Review redirect service running on port ${PORT}`);
      console.log(`Public redirect format: https://your-deployed-domain/r/CARD_ID`);
    });
  })
  .catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
