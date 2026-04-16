/**
 * ═══════════════════════════════════════════════════════
 *  ScanNaija — Self-Hosted Product Security Server v2.2
 *  Node.js + Express  |  SQLite (via better-sqlite3)
 * ═══════════════════════════════════════════════════════
 */

'use strict';

const express  = require('express');
const cors     = require('cors');
const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');

// ── Config ────────────────────────────────────────────
const PORT    = process.env.PORT    || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'scannaija.db');

// Set SCANNAIJA_ALLOWED_ORIGINS as comma-separated list in production, e.g.:
//   SCANNAIJA_ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
const ALLOWED_ORIGINS = process.env.SCANNAIJA_ALLOWED_ORIGINS
  ? process.env.SCANNAIJA_ALLOWED_ORIGINS.split(',').map(s => s.trim())
  : ['http://localhost:3000', 'http://127.0.0.1:3000'];

// ── DB init ───────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS companies (
    slug          TEXT PRIMARY KEY,
    nameOfCompany TEXT NOT NULL,
    regNo         TEXT,
    email         TEXT,
    mfrId         TEXT,
    createdAt     TEXT DEFAULT (datetime('now')),
    updatedAt     TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS products (
    barcode       TEXT PRIMARY KEY,
    barcodeSlug   TEXT NOT NULL,
    companyName   TEXT NOT NULL,
    companySlug   TEXT NOT NULL,
    mfrId         TEXT,
    productName   TEXT,
    category      TEXT,
    size          TEXT,
    price         TEXT,
    mfd           TEXT,
    expiry        TEXT,
    registeredAt  TEXT,
    syncedAt      TEXT DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_products_companySlug ON products(companySlug);
  CREATE INDEX IF NOT EXISTS idx_products_barcodeSlug ON products(barcodeSlug);

  CREATE TABLE IF NOT EXISTS api_keys (
    key_hash      TEXT PRIMARY KEY,
    company_slug  TEXT NOT NULL,
    label         TEXT DEFAULT '',
    created_at    TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS piracy_flags (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    barcode        TEXT NOT NULL,
    claimedCompany TEXT,
    realCompany    TEXT,
    ts             TEXT NOT NULL,
    createdAt      TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS piracy_flag_seen (
    flag_id       INTEGER NOT NULL REFERENCES piracy_flags(id) ON DELETE CASCADE,
    company_slug  TEXT    NOT NULL,
    seen_at       TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (flag_id, company_slug)
  );
`);

// ── In-memory rate limiter ────────────────────────────
const rateLimitStore = new Map();

function rateLimit({ windowMs = 60_000, max = 30 } = {}) {
  return (req, res, next) => {
    const ip  = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();
    let entry = rateLimitStore.get(ip);

    if (!entry || now - entry.windowStart > windowMs) {
      entry = { count: 1, windowStart: now };
    } else {
      entry.count++;
    }
    rateLimitStore.set(ip, entry);

    if (rateLimitStore.size > 1000) {
      for (const [k, v] of rateLimitStore) {
        if (now - v.windowStart > windowMs) rateLimitStore.delete(k);
      }
    }

    if (entry.count > max) {
      return res.status(429).json({ ok: false, error: 'Too many requests. Please slow down.' });
    }
    next();
  };
}

// ── Prepared statements ───────────────────────────────
const stmts = {
  upsertCompany: db.prepare(`
    INSERT INTO companies (slug,nameOfCompany,regNo,email,mfrId,updatedAt)
    VALUES (@slug,@nameOfCompany,@regNo,@email,@mfrId,datetime('now'))
    ON CONFLICT(slug) DO UPDATE SET
      nameOfCompany=excluded.nameOfCompany, regNo=excluded.regNo,
      email=excluded.email, mfrId=excluded.mfrId, updatedAt=datetime('now')
  `),

  upsertProduct: db.prepare(`
    INSERT INTO products
      (barcode,barcodeSlug,companyName,companySlug,mfrId,productName,category,size,price,mfd,expiry,registeredAt,syncedAt)
    VALUES
      (@barcode,@barcodeSlug,@companyName,@companySlug,@mfrId,@productName,@category,@size,@price,@mfd,@expiry,@registeredAt,datetime('now'))
    ON CONFLICT(barcode) DO UPDATE SET
      companyName=excluded.companyName, companySlug=excluded.companySlug,
      mfrId=excluded.mfrId, productName=excluded.productName,
      category=excluded.category, size=excluded.size, price=excluded.price,
      mfd=excluded.mfd, expiry=excluded.expiry,
      registeredAt=excluded.registeredAt, syncedAt=datetime('now')
  `),

  getProductBySlug: db.prepare(`SELECT * FROM products WHERE barcodeSlug=? LIMIT 1`),
  getCompanyBySlug: db.prepare(`SELECT * FROM companies WHERE slug=? LIMIT 1`),

  insertFlag: db.prepare(`
    INSERT INTO piracy_flags (barcode,claimedCompany,realCompany,ts)
    VALUES (@barcode,@claimedCompany,@realCompany,@ts)
  `),

  getUnseenFlags: db.prepare(`
    SELECT pf.* FROM piracy_flags pf
    WHERE pf.realCompany = @realCompany
      AND NOT EXISTS (
        SELECT 1 FROM piracy_flag_seen pfs
        WHERE pfs.flag_id = pf.id AND pfs.company_slug = @slug
      )
    ORDER BY pf.createdAt DESC LIMIT 50
  `),

  markFlagSeen:   db.prepare(`INSERT OR IGNORE INTO piracy_flag_seen (flag_id, company_slug) VALUES (?, ?)`),
  insertApiKey:   db.prepare(`INSERT INTO api_keys (key_hash, company_slug, label) VALUES (?,?,?)`),
  lookupApiKey:   db.prepare(`SELECT * FROM api_keys WHERE key_hash=? LIMIT 1`),
  listApiKeys:    db.prepare(`SELECT key_hash, company_slug, label, created_at FROM api_keys WHERE company_slug=?`),
  deleteApiKey:   db.prepare(`DELETE FROM api_keys WHERE key_hash=? AND company_slug=?`),
};

// ── Helpers ───────────────────────────────────────────
function slugify(str) {
  return (str || '').toString().toLowerCase()
    .replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '').slice(0, 180);
}
function hashKey(raw)    { return crypto.createHash('sha256').update(raw).digest('hex'); }
function generateApiKey(){ return 'sn_' + crypto.randomBytes(20).toString('hex'); }
function ok(res, data={})       { res.json({ ok: true, ...data }); }
function err(res, msg, code=400){ res.status(code).json({ ok: false, error: msg }); }

// ── Auth middleware ───────────────────────────────────
function requireApiKey(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const headerKey  = req.headers['x-api-key']     || '';
  const rawKey     = headerKey || (authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '');

  if (!rawKey) return err(res, 'API key required (X-API-Key header or Authorization: Bearer <key>)', 401);

  const row = stmts.lookupApiKey.get(hashKey(rawKey));
  if (!row) return err(res, 'Invalid or revoked API key', 401);

  req.companySlug  = row.company_slug;
  req.apiKeyRecord = row;
  next();
}

// ── App ───────────────────────────────────────────────
const app = express();

const corsOptions = {
  origin(origin, callback) {
    if (!origin) return callback(null, true); // curl / same-origin / mobile
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error(`CORS: origin "${origin}" is not allowed`));
  },
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  credentials: true,
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '2mb' }));

const frontendPath = path.join(__dirname, 'public', 'index.html');
if (fs.existsSync(frontendPath)) {
  app.use(express.static(path.join(__dirname, 'public')));
}

// ── Health ────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  ok(res, { service: 'ScanNaija', version: '2.2', time: new Date().toISOString() });
});

// ── API Key management ────────────────────────────────
// Bootstrap: if no keys exist for a slug yet, allow creation without auth.
// Subsequent keys require an existing valid key for that company.
app.post('/api/keys/generate', (req, res) => {
  const { company_slug, label } = req.body || {};
  if (!company_slug) return err(res, 'company_slug required');

  const slug        = slugify(company_slug);
  const existingKeys = stmts.listApiKeys.all(slug);

  if (existingKeys.length > 0) {
    const authHeader = req.headers['authorization'] || '';
    const headerKey  = req.headers['x-api-key']     || '';
    const rawKey     = headerKey || (authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '');
    if (!rawKey) return err(res, 'API key required to generate additional keys', 401);
    const row = stmts.lookupApiKey.get(hashKey(rawKey));
    if (!row || row.company_slug !== slug) return err(res, 'Invalid or revoked API key', 401);
  }

  const raw = generateApiKey();
  stmts.insertApiKey.run(hashKey(raw), slug, label || '');
  ok(res, { api_key: raw, company_slug: slug, warning: 'Store this key safely — it will not be shown again.' });
});

app.get('/api/keys', requireApiKey, (req, res) => {
  const keys = stmts.listApiKeys.all(req.companySlug).map(k => ({
    key_preview:  'sn_' + k.key_hash.slice(0, 8) + '…',
    label:        k.label,
    company_slug: k.company_slug,
    created_at:   k.created_at,
  }));
  ok(res, { keys });
});

app.delete('/api/keys', requireApiKey, (req, res) => {
  const { api_key } = req.body || {};
  if (!api_key) return err(res, 'api_key required');
  const result = stmts.deleteApiKey.run(hashKey(api_key), req.companySlug);
  if (result.changes === 0) return err(res, 'Key not found or does not belong to your company', 404);
  ok(res, { message: 'Key revoked' });
});

// ── Company register / update  [protected] ────────────
app.post('/api/company', requireApiKey, (req, res) => {
  const { slug, nameOfCompany, regNo, email, mfrId } = req.body || {};
  if (!slug || !nameOfCompany) return err(res, 'slug and nameOfCompany required');

  const companySlug = slugify(slug);
  if (companySlug !== req.companySlug)
    return err(res, 'API key is not authorised for this company', 403);

  try {
    stmts.upsertCompany.run({ slug: companySlug, nameOfCompany, regNo: regNo||'', email: email||'', mfrId: mfrId||'' });
    ok(res, { message: 'Company registered' });
  } catch(e) { console.error(e); err(res, 'DB error', 500); }
});

// ── Bulk product sync  [protected] ───────────────────
app.post('/api/products/bulk', requireApiKey, (req, res) => {
  const { products } = req.body || {};
  if (!Array.isArray(products)) return err(res, 'products array required');

  const foreign = products.find(p => p.companySlug && slugify(p.companySlug) !== req.companySlug);
  if (foreign) return err(res, 'Cannot sync products for a different company', 403);

  const syncMany = db.transaction((rows) => {
    for (const p of rows) {
      if (!p.barcode) continue;
      stmts.upsertProduct.run({
        barcode: p.barcode, barcodeSlug: slugify(p.barcode),
        companyName: p.companyName||'', companySlug: req.companySlug,
        mfrId: p.mfrId||'', productName: p.productName||'',
        category: p.category||'', size: p.size||'', price: p.price||'',
        mfd: p.mfd||'', expiry: p.expiry||'',
        registeredAt: p.registeredAt || new Date().toLocaleDateString('en-NG'),
      });
    }
  });

  try {
    syncMany(products);
    ok(res, { synced: products.length });
  } catch(e) { console.error(e); err(res, 'DB error', 500); }
});

// ── Verify barcode  [public, rate-limited] ────────────
app.get('/api/verify/barcode/:code',
  rateLimit({ windowMs: 60_000, max: 60 }),
  (req, res) => {
    const slug = slugify(decodeURIComponent(req.params.code));
    const row  = stmts.getProductBySlug.get(slug);
    if (!row) return res.json({ found: false });
    res.json({ found: true, product: row });
  }
);

// ── Verify company  [public, rate-limited] ────────────
app.get('/api/verify/company/:name',
  rateLimit({ windowMs: 60_000, max: 60 }),
  (req, res) => {
    const slug = slugify(decodeURIComponent(req.params.name));
    const row  = stmts.getCompanyBySlug.get(slug);
    if (!row) return res.json({ found: false });
    res.json({ found: true, company: row });
  }
);

// ── File piracy flag  [public, rate-limited] ──────────
app.post('/api/piracy/flag',
  rateLimit({ windowMs: 60_000, max: 20 }),
  (req, res) => {
    const { barcode, claimedCompany, realCompany, ts } = req.body || {};
    if (!barcode || !claimedCompany) return err(res, 'barcode and claimedCompany required');
    try {
      stmts.insertFlag.run({ barcode, claimedCompany, realCompany: realCompany||'', ts: ts||new Date().toISOString() });
      ok(res, { message: 'Piracy flag recorded' });
    } catch(e) { console.error(e); err(res, 'DB error', 500); }
  }
);

// ── Poll piracy flags  [protected] ───────────────────
app.get('/api/piracy/flags/:company', requireApiKey, (req, res) => {
  const companyName = decodeURIComponent(req.params.company);
  const slug        = slugify(companyName);
  if (slug !== req.companySlug) return err(res, 'API key is not authorised for this company', 403);

  try {
    const flags = stmts.getUnseenFlags.all({ realCompany: companyName, slug });
    for (const f of flags) stmts.markFlagSeen.run(f.id, slug);
    res.json({ flags });
  } catch(e) { console.error(e); err(res, 'DB error', 500); }
});

// ── 404 ───────────────────────────────────────────────
app.use((_req, res) => { err(res, 'Not found', 404); });

// ── Start ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════╗
  ║   ScanNaija Server  v2.2              ║
  ║   http://localhost:${PORT}               ║
  ║   DB: ${DB_PATH.slice(-30).padStart(30)} ║
  ╚═══════════════════════════════════════╝

  CORS allowed origins: ${ALLOWED_ORIGINS.join(', ')}

  First-time setup — generate your first API key:
    curl -X POST http://localhost:${PORT}/api/keys/generate \\
         -H "Content-Type: application/json" \\
         -d '{"company_slug":"your-company","label":"main key"}'
  `);
});
