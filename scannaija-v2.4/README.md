# ScanNaija Server — Self-Hosted Setup Guide

## Stack
- **Runtime**: Node.js 18+
- **Framework**: Express
- **Database**: SQLite (via `better-sqlite3` — zero external DB needed)
- **Frontend**: Plain HTML/JS (the `barcode_fixed.html` file)

---

## Quick Start (Local / VPS)

```bash
# 1. Install dependencies
npm install

# 2. Start the server
npm start
# → Server running at http://localhost:3000
```

Open `barcode_fixed.html` in your browser. Go to **Settings → Server Configuration** and enter your API key (see First-Time Setup below).

---

## First-Time Setup — API Keys

The manufacturer endpoints (sync, piracy polling) require an API key. Public buyer endpoints (verify barcode/company, file a flag) remain open.

**Bootstrap your first key** (no auth needed when no keys exist yet for a company):

```bash
curl -X POST http://localhost:3000/api/keys/generate \
     -H "Content-Type: application/json" \
     -d '{"company_slug":"your-company-name","label":"main key"}'
```

Response:
```json
{
  "ok": true,
  "api_key": "sn_abc123...",
  "warning": "Store this key safely — it will not be shown again."
}
```

Copy the `api_key` value, then in the frontend go to **Settings → Server Configuration** and paste it into the API Key field. Click **Save**.

**Generating additional keys** (requires your existing key):
```bash
curl -X POST http://localhost:3000/api/keys/generate \
     -H "X-API-Key: sn_abc123..." \
     -H "Content-Type: application/json" \
     -d '{"company_slug":"your-company-name","label":"backup key"}'
```

**Revoking a key:**
```bash
curl -X DELETE http://localhost:3000/api/keys \
     -H "X-API-Key: sn_abc123..." \
     -H "Content-Type: application/json" \
     -d '{"api_key":"sn_keytorevoke..."}'
```

---

## Deploying to a VPS (e.g. Ubuntu on DigitalOcean / AWS / Hetzner)

### 1. Upload files
```bash
scp -r scannaija-server/ user@YOUR_SERVER_IP:/home/user/
scp barcode_fixed.html   user@YOUR_SERVER_IP:/home/user/scannaija-server/public/index.html
```

### 2. Install Node.js on the server
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### 3. Install dependencies & start
```bash
cd /home/user/scannaija-server
npm install
npm start
```

### 4. Keep it alive with PM2
```bash
npm install -g pm2
pm2 start server.js --name scannaija
pm2 save
pm2 startup    # follow the printed command to auto-start on reboot
```

### 5. Set CORS to your frontend domain
In production, set the `SCANNAIJA_ALLOWED_ORIGINS` environment variable:

```bash
# PM2 example
pm2 start server.js --name scannaija \
  --env-var SCANNAIJA_ALLOWED_ORIGINS=https://yourdomain.com

# Or with a .env / systemd EnvironmentFile:
SCANNAIJA_ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
```

The server refuses requests from any origin not in this list. Defaults to `localhost:3000` only.

### 6. Point the frontend at your server
In the app, go to **Settings → Server Configuration**, set the Server URL to your server's public URL (e.g. `https://api.yourdomain.com`) and paste your API key. Click **Save**.

### 7. (Optional) Reverse proxy with Nginx + HTTPS
```nginx
server {
    listen 80;
    server_name api.yourdomain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```
Then get a free SSL cert:
```bash
sudo certbot --nginx -d api.yourdomain.com
```

---

## Deploying to Railway / Render (Free tier)

1. Push the `scannaija-server/` folder to a GitHub repo
2. On **Railway**: New Project → Deploy from GitHub → select repo
3. On **Render**: New Web Service → select repo → Build: `npm install` → Start: `node server.js`
4. Set env vars:
   - `PORT` (set automatically by most platforms)
   - `SCANNAIJA_ALLOWED_ORIGINS=https://your-frontend-domain.com`
5. Copy the provided URL (e.g. `https://scannaija.up.railway.app`) and enter it in **Settings → Server Configuration** in the frontend

---

## Environment Variables

| Variable                    | Default                          | Description                                      |
|-----------------------------|----------------------------------|--------------------------------------------------|
| `PORT`                      | `3000`                           | Port the server listens on                       |
| `DB_PATH`                   | `./scannaija.db`                 | Path to SQLite database file                     |
| `SCANNAIJA_ALLOWED_ORIGINS` | `http://localhost:3000` only     | Comma-separated list of allowed CORS origins     |

---

## API Reference

### Public endpoints (no key required)
| Method | Endpoint                          | Description                             |
|--------|-----------------------------------|-----------------------------------------|
| GET    | `/api/health`                     | Health check                            |
| GET    | `/api/verify/barcode/:code`       | Buyer verifies a barcode (60 req/min)   |
| GET    | `/api/verify/company/:name`       | Buyer checks if a company is registered (60 req/min) |
| POST   | `/api/piracy/flag`                | Buyer files a counterfeit report (20 req/min) |

### Protected endpoints (API key required)
Pass your key as `X-API-Key: sn_...` or `Authorization: Bearer sn_...`

| Method | Endpoint                          | Description                              |
|--------|-----------------------------------|------------------------------------------|
| POST   | `/api/keys/generate`              | Generate an API key (bootstrap or authed)|
| GET    | `/api/keys`                       | List your company's key metadata         |
| DELETE | `/api/keys`                       | Revoke an API key                        |
| POST   | `/api/company`                    | Register or update your company          |
| POST   | `/api/products/bulk`              | Sync all products for your company       |
| GET    | `/api/piracy/flags/:company`      | Poll for new piracy reports              |

Keys are scoped per company — a key for company A cannot modify company B's data.

---

## Database

The SQLite database (`scannaija.db`) is created automatically on first run. Back it up by copying this file.

Tables: `companies`, `products`, `api_keys`, `piracy_flags`, `piracy_flag_seen`

To reset: delete `scannaija.db` and restart the server (you will need to generate a new API key).

---

## Security Notes for Production

- ✅ API keys protect all manufacturer write endpoints (built-in)
- ✅ CORS is restricted to your configured origins (built-in)
- ✅ Rate limiting on all public endpoints (built-in)
- ✅ Piracy flag seen-tracking uses a proper junction table (built-in)
- ➕ Run behind HTTPS (Nginx + Let's Encrypt)
- ➕ Keep `scannaija.db` outside the web root and back it up regularly
- ➕ Set `SCANNAIJA_ALLOWED_ORIGINS` before going live
