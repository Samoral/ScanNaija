/**
 * ═══════════════════════════════════════════════════════
 *  ScanNaija — Self-Hosted Product Security Server v2.3
 *  Node.js + Express  |  MongoDB (via mongodb driver)
 * ═══════════════════════════════════════════════════════
 */

'use strict';

const express      = require('express');
const cors         = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const path         = require('path');
const fs           = require('fs');
const crypto       = require('crypto');

// ── Config ────────────────────────────────────────────
const PORT       = process.env.PORT       || 3000;
const MONGO_URI  = process.env.MONGO_URI  || 'mongodb://127.0.0.1:27017';
const MONGO_DB   = process.env.MONGO_DB   || 'scannaija';

const ALLOWED_ORIGINS = process.env.SCANNAIJA_ALLOWED_ORIGINS
  ? process.env.SCANNAIJA_ALLOWED_ORIGINS.split(',').map(s => s.trim())
  : ['http://localhost:3000', 'http://127.0.0.1:3000'];

// ── MongoDB connection ────────────────────────────────
const client = new MongoClient(MONGO_URI);
let db; // filled after connect()

async function connectDB() {
  await client.connect();
  db = client.db(MONGO_DB);

  // Indexes (idempotent)
  await db.collection('companies').createIndex({ slug: 1 }, { unique: true });
  await db.collection('products').createIndex({ barcode: 1 }, { unique: true });
  await db.collection('products').createIndex({ barcodeSlug: 1 });
  await db.collection('products').createIndex({ companySlug: 1 });
  await db.collection('api_keys').createIndex({ key_hash: 1 }, { unique: true });
  await db.collection('api_keys').createIndex({ company_slug: 1 });
  await db.collection('piracy_flags').createIndex({ realCompany: 1 });
  await db.collection('piracy_flag_seen').createIndex(
    { flag_id: 1, company_slug: 1 }, { unique: true }
  );

  console.log(`MongoDB connected → ${MONGO_URI} / ${MONGO_DB}`);
}

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
      for (const [k, v] of rateLimitStore)
        if (now - v.windowStart > windowMs) rateLimitStore.delete(k);
    }

    if (entry.count > max)
      return res.status(429).json({ ok: false, error: 'Too many requests. Please slow down.' });
    next();
  };
}

// ── Helpers ───────────────────────────────────────────
function slugify(str) {
  return (str || '').toString().toLowerCase()
    .replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '').slice(0, 180);
}
function hashKey(raw)     { return crypto.createHash('sha256').update(raw).digest('hex'); }
function generateApiKey() { return 'sn_' + crypto.randomBytes(20).toString('hex'); }
function ok(res, data={})        { res.json({ ok: true, ...data }); }
function err(res, msg, code=400) { res.status(code).json({ ok: false, error: msg }); }

// ── Auth middleware ───────────────────────────────────
async function requireApiKey(req, res, next) {
  try {
    const authHeader = req.headers['authorization'] || '';
    const headerKey  = req.headers['x-api-key']     || '';
    const rawKey     = headerKey || (authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '');

    if (!rawKey)
      return err(res, 'API key required (X-API-Key header or Authorization: Bearer <key>)', 401);

    const row = await db.collection('api_keys').findOne({ key_hash: hashKey(rawKey) });
    if (!row) return err(res, 'Invalid or revoked API key', 401);

    req.companySlug  = row.company_slug;
    req.apiKeyRecord = row;
    next();
  } catch (e) { console.error(e); err(res, 'Auth error', 500); }
}

// ── App ───────────────────────────────────────────────
const app = express();

const corsOptions = {
  origin(origin, callback) {
    if (!origin) return callback(null, true);
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
  ok(res, { service: 'ScanNaija', version: '2.3', time: new Date().toISOString() });
});

// ── API Key management ────────────────────────────────
app.post('/api/keys/generate', async (req, res) => {
  try {
    const { company_slug, label } = req.body || {};
    if (!company_slug) return err(res, 'company_slug required');

    const slug        = slugify(company_slug);
    const existingKeys = await db.collection('api_keys').find({ company_slug: slug }).toArray();

    if (existingKeys.length > 0) {
      const authHeader = req.headers['authorization'] || '';
      const headerKey  = req.headers['x-api-key']     || '';
      const rawKey     = headerKey || (authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '');
      if (!rawKey) return err(res, 'API key required to generate additional keys', 401);
      const row = await db.collection('api_keys').findOne({ key_hash: hashKey(rawKey) });
      if (!row || row.company_slug !== slug) return err(res, 'Invalid or revoked API key', 401);
    }

    const raw = generateApiKey();
    await db.collection('api_keys').insertOne({
      key_hash:     hashKey(raw),
      company_slug: slug,
      label:        label || '',
      created_at:   new Date().toISOString(),
    });

    ok(res, { api_key: raw, company_slug: slug, warning: 'Store this key safely — it will not be shown again.' });
  } catch (e) { console.error(e); err(res, 'DB error', 500); }
});

app.get('/api/keys', requireApiKey, async (req, res) => {
  try {
    const keys = await db.collection('api_keys')
      .find({ company_slug: req.companySlug })
      .toArray();

    ok(res, {
      keys: keys.map(k => ({
        key_preview:  'sn_' + k.key_hash.slice(0, 8) + '…',
        label:        k.label,
        company_slug: k.company_slug,
        created_at:   k.created_at,
      })),
    });
  } catch (e) { console.error(e); err(res, 'DB error', 500); }
});

app.delete('/api/keys', requireApiKey, async (req, res) => {
  try {
    const { api_key } = req.body || {};
    if (!api_key) return err(res, 'api_key required');

    const result = await db.collection('api_keys').deleteOne({
      key_hash:     hashKey(api_key),
      company_slug: req.companySlug,
    });

    if (result.deletedCount === 0)
      return err(res, 'Key not found or does not belong to your company', 404);

    ok(res, { message: 'Key revoked' });
  } catch (e) { console.error(e); err(res, 'DB error', 500); }
});

// ── Company register / update  [protected] ────────────
app.post('/api/company', requireApiKey, async (req, res) => {
  try {
    const { slug, nameOfCompany, regNo, email, mfrId } = req.body || {};
    if (!slug || !nameOfCompany) return err(res, 'slug and nameOfCompany required');

    const companySlug = slugify(slug);
    if (companySlug !== req.companySlug)
      return err(res, 'API key is not authorised for this company', 403);

    await db.collection('companies').updateOne(
      { slug: companySlug },
      {
        $set: {
          slug: companySlug, nameOfCompany,
          regNo: regNo || '', email: email || '', mfrId: mfrId || '',
          updatedAt: new Date().toISOString(),
        },
        $setOnInsert: { createdAt: new Date().toISOString() },
      },
      { upsert: true }
    );

    ok(res, { message: 'Company registered' });
  } catch (e) { console.error(e); err(res, 'DB error', 500); }
});

// ── Bulk product sync  [protected] ───────────────────
app.post('/api/products/bulk', requireApiKey, async (req, res) => {
  try {
    const { products } = req.body || {};
    if (!Array.isArray(products)) return err(res, 'products array required');

    const foreign = products.find(p => p.companySlug && slugify(p.companySlug) !== req.companySlug);
    if (foreign) return err(res, 'Cannot sync products for a different company', 403);

    if (products.length === 0) return ok(res, { synced: 0 });

    const ops = products
      .filter(p => p.barcode)
      .map(p => ({
        updateOne: {
          filter: { barcode: p.barcode },
          update: {
            $set: {
              barcode:      p.barcode,
              barcodeSlug:  slugify(p.barcode),
              companyName:  p.companyName   || '',
              companySlug:  req.companySlug,
              mfrId:        p.mfrId         || '',
              productName:  p.productName   || '',
              category:     p.category      || '',
              size:         p.size          || '',
              price:        p.price         || '',
              mfd:          p.mfd           || '',
              expiry:       p.expiry        || '',
              registeredAt: p.registeredAt  || new Date().toLocaleDateString('en-NG'),
              syncedAt:     new Date().toISOString(),
            },
          },
          upsert: true,
        },
      }));

    await db.collection('products').bulkWrite(ops, { ordered: false });
    ok(res, { synced: ops.length });
  } catch (e) { console.error(e); err(res, 'DB error', 500); }
});

// ── Verify barcode  [public, rate-limited] ────────────
app.get('/api/verify/barcode/:code',
  rateLimit({ windowMs: 60_000, max: 60 }),
  async (req, res) => {
    try {
      const slug = slugify(decodeURIComponent(req.params.code));
      const row  = await db.collection('products').findOne({ barcodeSlug: slug });
      if (!row) return res.json({ found: false });
      res.json({ found: true, product: row });
    } catch (e) { console.error(e); err(res, 'DB error', 500); }
  }
);

// ── Verify company  [public, rate-limited] ────────────
app.get('/api/verify/company/:name',
  rateLimit({ windowMs: 60_000, max: 60 }),
  async (req, res) => {
    try {
      const slug = slugify(decodeURIComponent(req.params.name));
      const row  = await db.collection('companies').findOne({ slug });
      if (!row) return res.json({ found: false });
      res.json({ found: true, company: row });
    } catch (e) { console.error(e); err(res, 'DB error', 500); }
  }
);

// ── File piracy flag  [public, rate-limited] ──────────
app.post('/api/piracy/flag',
  rateLimit({ windowMs: 60_000, max: 20 }),
  async (req, res) => {
    try {
      const { barcode, claimedCompany, realCompany, ts } = req.body || {};
      if (!barcode || !claimedCompany) return err(res, 'barcode and claimedCompany required');

      await db.collection('piracy_flags').insertOne({
        barcode,
        claimedCompany,
        realCompany: realCompany || '',
        ts:          ts          || new Date().toISOString(),
        createdAt:   new Date().toISOString(),
      });

      ok(res, { message: 'Piracy flag recorded' });
    } catch (e) { console.error(e); err(res, 'DB error', 500); }
  }
);

// ── Poll piracy flags  [protected] ───────────────────
app.get('/api/piracy/flags/:company', requireApiKey, async (req, res) => {
  try {
    const companyName = decodeURIComponent(req.params.company);
    const slug        = slugify(companyName);
    if (slug !== req.companySlug) return err(res, 'API key is not authorised for this company', 403);

    // Get IDs of flags already seen by this company
    const seenRecords = await db.collection('piracy_flag_seen')
      .find({ company_slug: slug })
      .toArray();
    const seenIds = seenRecords.map(s => s.flag_id.toString());

    // Fetch unseen flags for this company (most recent first, limit 50)
    const allFlags = await db.collection('piracy_flags')
      .find({ realCompany: companyName })
      .sort({ createdAt: -1 })
      .limit(50)
      .toArray();

    const flags = allFlags.filter(f => !seenIds.includes(f._id.toString()));

    // Mark them as seen
    if (flags.length > 0) {
      const seenOps = flags.map(f => ({
        updateOne: {
          filter:  { flag_id: f._id, company_slug: slug },
          update:  { $setOnInsert: { flag_id: f._id, company_slug: slug, seen_at: new Date().toISOString() } },
          upsert:  true,
        },
      }));
      await db.collection('piracy_flag_seen').bulkWrite(seenOps, { ordered: false });
    }

    res.json({ flags });
  } catch (e) { console.error(e); err(res, 'DB error', 500); }
});

// ── 404 ───────────────────────────────────────────────
app.use((_req, res) => { err(res, 'Not found', 404); });

// ── Start ─────────────────────────────────────────────
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`
  ╔═══════════════════════════════════════╗
  ║   ScanNaija Server  v2.3              ║
  ║   http://localhost:${PORT}               ║
  ║   DB: MongoDB / ${MONGO_DB.padStart(20)} ║
  ╚═══════════════════════════════════════╝

  CORS allowed origins: ${ALLOWED_ORIGINS.join(', ')}

  First-time setup — generate your first API key:
    curl -X POST http://localhost:${PORT}/api/keys/generate \\
         -H "Content-Type: application/json" \\
         -d '{"company_slug":"your-company","label":"main key"}'
  `);
  });
}).catch(e => {
  console.error('Failed to connect to MongoDB:', e.message);
  process.exit(1);
});
