const express = require('express');
const cors = require('cors');
const { createClient } = require('@libsql/client');

const app = express();
app.use(cors());
app.use(express.json());

// ---- Config ----
const GOOGLE_REVIEW_URL_DEFAULT = process.env.GOOGLE_REVIEW_URL || 'https://g.page/r/REPLACE_ME/review';
const ADMIN_KEY = process.env.ADMIN_KEY || 'changeme'; // master password — sees every client
const PORT = process.env.PORT || 3000;

const TURSO_URL = process.env.TURSO_DATABASE_URL;
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN;

if (!TURSO_URL || !TURSO_TOKEN) {
  console.error('Missing TURSO_DATABASE_URL or TURSO_AUTH_TOKEN environment variables.');
}

const db = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });

// ---- DB setup ----
async function initDb() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS clients (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      password TEXT NOT NULL,
      google_review_url TEXT,
      created_at TEXT NOT NULL
    )
  `);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS cards (
      id TEXT PRIMARY KEY,
      label TEXT NOT NULL,
      client_id TEXT,
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
  // best-effort migration: add client_id / google_review_url columns if they don't exist yet
  try { await db.execute('ALTER TABLE cards ADD COLUMN client_id TEXT'); } catch (e) {}
  try { await db.execute('ALTER TABLE clients ADD COLUMN google_review_url TEXT'); } catch (e) {}
}

function slugify(s) {
  return s.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || Math.random().toString(36).slice(2, 8);
}

function hashIp(ip) {
  let h = 0;
  for (let i = 0; i < ip.length; i++) { h = (h << 5) - h + ip.charCodeAt(i); h |= 0; }
  return String(h);
}

// ---- Auth middleware ----
// Master key (ADMIN_KEY) => full access to every client.
// A client's own password => scoped access to only their cards.
async function authenticate(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key) return res.status(401).json({ error: 'unauthorized' });

  if (key === ADMIN_KEY) {
    req.scope = { isMaster: true, clientId: null };
    return next();
  }

  try {
    const result = await db.execute({ sql: 'SELECT * FROM clients WHERE password = ?', args: [key] });
    if (result.rows.length > 0) {
      const client = result.rows[0];
      req.scope = { isMaster: false, clientId: client.id, clientName: client.name };
      return next();
    }
  } catch (err) {
    console.error(err);
  }

  return res.status(401).json({ error: 'unauthorized' });
}

// ---- Public redirect route (no auth — this is what's on the physical card) ----
app.get('/r/:cardId', async (req, res) => {
  const { cardId } = req.params;
  try {
    const cardResult = await db.execute({ sql: 'SELECT * FROM cards WHERE id = ?', args: [cardId] });
    if (cardResult.rows.length === 0) {
      return res.redirect(302, GOOGLE_REVIEW_URL_DEFAULT);
    }
    const card = cardResult.rows[0];

    let targetUrl = GOOGLE_REVIEW_URL_DEFAULT;
    if (card.client_id) {
      const clientResult = await db.execute({ sql: 'SELECT google_review_url FROM clients WHERE id = ?', args: [card.client_id] });
      if (clientResult.rows[0]?.google_review_url) {
        targetUrl = clientResult.rows[0].google_review_url;
      }
    }

    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    await db.execute({
      sql: 'INSERT INTO scans (card_id, ts, ua, ip_hash) VALUES (?, ?, ?, ?)',
      args: [cardId, new Date().toISOString(), req.headers['user-agent'] || '', ip ? hashIp(ip) : '']
    });

    res.redirect(302, targetUrl);
  } catch (err) {
    console.error('Redirect error:', err);
    res.redirect(302, GOOGLE_REVIEW_URL_DEFAULT);
  }
});

// ---- Client management (master only) ----
app.post('/api/clients', authenticate, async (req, res) => {
  if (!req.scope.isMaster) return res.status(403).json({ error: 'master access only' });
  const { name, password, googleReviewUrl } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'name and password required' });
  const id = slugify(name) + '-' + Math.random().toString(36).slice(2, 5);
  try {
    await db.execute({
      sql: 'INSERT INTO clients (id, name, password, google_review_url, created_at) VALUES (?, ?, ?, ?, ?)',
      args: [id, name, password, googleReviewUrl || null, new Date().toISOString()]
    });
    res.json({ ok: true, id, name, password });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

app.get('/api/clients', authenticate, async (req, res) => {
  if (!req.scope.isMaster) return res.status(403).json({ error: 'master access only' });
  const result = await db.execute('SELECT id, name, password, google_review_url, created_at FROM clients ORDER BY created_at DESC');
  res.json(result.rows);
});

app.delete('/api/clients/:id', authenticate, async (req, res) => {
  if (!req.scope.isMaster) return res.status(403).json({ error: 'master access only' });
  const clientId = req.params.id;
  try {
    const cardsResult = await db.execute({ sql: 'SELECT id FROM cards WHERE client_id = ?', args: [clientId] });
    for (const c of cardsResult.rows) {
      await db.execute({ sql: 'DELETE FROM scans WHERE card_id = ?', args: [c.id] });
    }
    await db.execute({ sql: 'DELETE FROM cards WHERE client_id = ?', args: [clientId] });
    await db.execute({ sql: 'DELETE FROM clients WHERE id = ?', args: [clientId] });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

// ---- Cards API (scoped) ----
app.get('/api/cards', authenticate, async (req, res) => {
  try {
    let cardsResult;
    if (req.scope.isMaster) {
      const filterClient = req.query.client_id;
      cardsResult = filterClient
        ? await db.execute({ sql: 'SELECT * FROM cards WHERE client_id = ? ORDER BY created_at DESC', args: [filterClient] })
        : await db.execute('SELECT * FROM cards ORDER BY created_at DESC');
    } else {
      cardsResult = await db.execute({ sql: 'SELECT * FROM cards WHERE client_id = ? ORDER BY created_at DESC', args: [req.scope.clientId] });
    }
    const countsResult = await db.execute('SELECT card_id, COUNT(*) as total FROM scans GROUP BY card_id');
    const countMap = Object.fromEntries(countsResult.rows.map(r => [r.card_id, Number(r.total)]));
    res.json(cardsResult.rows.map(c => ({ ...c, totalScans: countMap[c.id] || 0 })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

app.post('/api/cards', authenticate, async (req, res) => {
  const { id, label } = req.body;
  if (!id || !label) return res.status(400).json({ error: 'id and label required' });

  // Master can optionally assign a card to a client via body.clientId; clients always get their own id forced.
  const clientId = req.scope.isMaster ? (req.body.clientId || null) : req.scope.clientId;

  try {
    await db.execute({
      sql: 'INSERT INTO cards (id, label, client_id, created_at) VALUES (?, ?, ?, ?)',
      args: [id, label, clientId, new Date().toISOString()]
    });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

app.delete('/api/cards/:id', authenticate, async (req, res) => {
  try {
    if (!req.scope.isMaster) {
      const check = await db.execute({ sql: 'SELECT client_id FROM cards WHERE id = ?', args: [req.params.id] });
      if (check.rows.length === 0 || check.rows[0].client_id !== req.scope.clientId) {
        return res.status(403).json({ error: 'not your card' });
      }
    }
    await db.execute({ sql: 'DELETE FROM scans WHERE card_id = ?', args: [req.params.id] });
    await db.execute({ sql: 'DELETE FROM cards WHERE id = ?', args: [req.params.id] });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

app.get('/api/scans/daily', authenticate, async (req, res) => {
  try {
    let sql, args;
    if (req.scope.isMaster) {
      const filterClient = req.query.client_id;
      if (filterClient) {
        sql = `SELECT s.card_id, substr(s.ts,1,10) as date, COUNT(*) as count
               FROM scans s JOIN cards c ON c.id = s.card_id
               WHERE c.client_id = ? GROUP BY s.card_id, date ORDER BY date ASC`;
        args = [filterClient];
      } else {
        sql = `SELECT card_id, substr(ts,1,10) as date, COUNT(*) as count FROM scans GROUP BY card_id, date ORDER BY date ASC`;
        args = [];
      }
    } else {
      sql = `SELECT s.card_id, substr(s.ts,1,10) as date, COUNT(*) as count
             FROM scans s JOIN cards c ON c.id = s.card_id
             WHERE c.client_id = ? GROUP BY s.card_id, date ORDER BY date ASC`;
      args = [req.scope.clientId];
    }
    const result = await db.execute({ sql, args });
    res.json(result.rows.map(r => ({ ...r, count: Number(r.count) })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

app.get('/api/whoami', authenticate, (req, res) => {
  res.json({ isMaster: req.scope.isMaster, clientId: req.scope.clientId, clientName: req.scope.clientName || null });
});

app.get('/health', (req, res) => res.json({ ok: true }));

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Review redirect service running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
