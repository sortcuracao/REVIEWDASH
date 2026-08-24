# Review Card Redirect Service

Tracks scans per physical review card and redirects to your Google review link.

## Setup

1. `npm install`
2. Set env vars:
   - `GOOGLE_REVIEW_URL` — your Google review link (Business Profile > "Get more reviews" > share link)
   - `ADMIN_KEY` — any secret string, used to protect the admin API
   - `PORT` — defaults to 3000
3. `npm start`

## Deploy (fastest: Railway or Render, free tier works)

**Railway**
1. Push this folder to a GitHub repo
2. railway.app → New Project → Deploy from GitHub
3. Add the env vars above in Settings > Variables
4. Railway gives you a public URL, e.g. `https://yourapp.up.railway.app`

**Render**
Same flow: New Web Service → connect repo → build command `npm install`, start command `npm start` → add env vars.

## Using it

- Create a card: `POST /api/cards` with `{"id": "front-desk", "label": "Front Desk"}` and header `x-admin-key: YOUR_KEY`
- Print/generate a QR code pointing to: `https://your-deployed-domain/r/front-desk`
- Every scan logs to the database and redirects to `GOOGLE_REVIEW_URL`
- Pull stats: `GET /api/cards` and `GET /api/scans/daily` (both need the admin key header)

## Connecting to the dashboard artifact

Point the dashboard's fetch calls at your deployed URL instead of local storage, using the same `x-admin-key` header for `/api/cards` and `/api/scans/daily`.

## Notes

- SQLite file (`data.sqlite`) persists on disk — on Railway/Render this survives redeploys only if you attach a persistent volume; otherwise back it up periodically.
- IP addresses are hashed, not stored raw, for lightweight dedup only.
