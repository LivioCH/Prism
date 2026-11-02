# Prism Backend

REST API for the Prism anti-phishing Android app. Node 22+, Express, SQLite (built-in `node:sqlite`, no native deps), JWT auth.

## Run

```bash
npm install
cp .env.example .env        # set JWT_SECRET
export $(grep -v '^#' .env | xargs)
npm start                   # http://localhost:3000
npm test                    # 11 end-to-end tests
```

Production: set `NODE_ENV=production` and a strong `JWT_SECRET` (server refuses to start otherwise). Put it behind HTTPS (Caddy/nginx/a PaaS) and keep `DATABASE_PATH` on persistent storage.

## What it replaces in the app

| App code (`AppStateViewModel`)              | Endpoint                         |
|---------------------------------------------|----------------------------------|
| `handleSignUp` (fake 1.5s delay)            | `POST /api/auth/signup`          |
| `handleLogin` (fake 1.5s delay)             | `POST /api/auth/login`           |
| `handlePlanSelection` (SharedPreferences)   | `PUT /api/subscription`          |
| `handleScan` (`threats.random()`)           | `POST /api/scans`                |
| `autoScanClipboard` (`Math.random() > 0.6`) | `POST /api/scans` + `"source":"clipboard"` |
| `scanHistory` list                          | `GET /api/scans`                 |
| `scansToday/threatsBlocked/privacyAlerts/privacyScore` | `GET /api/stats`      |
| `clipboardMonitoring` toggle                | `PATCH /api/settings`            |

## API

All `/api/*` routes except `/api/auth/*` need `Authorization: Bearer <token>`. Errors look like
`{"error":{"code":"daily_limit","message":"...","limit":10}}`.

| Method & path | Body | Notes |
|---|---|---|
| `POST /api/auth/signup` | `{name,email,password}` | 201 -> `{token,user}`. Password >= 6 chars. 409 `email_taken` |
| `POST /api/auth/login` | `{email,password}` | 200 -> `{token,user}`. 401 `invalid_credentials` |
| `GET /api/me` | | `user.plan` is `null` until chosen -> show the plan modal |
| `PUT /api/subscription` | `{plan:"FREE"\|"PLUS"}` | **No payment verification yet** (see below) |
| `PATCH /api/settings` | `{clipboardMonitoring:boolean}` | |
| `GET /api/stats` | | `{scansToday,threatsBlocked,privacyAlerts,privacyScore,plan}` |
| `POST /api/scans` | `{type:"url"\|"phone"\|"message",content,source?:"manual"\|"clipboard"}` | 201 -> `{scan,signals[],showAlert}` |
| `GET /api/scans?limit=50&before=<ts>` | | Newest first. `nextBefore` is the cursor, `null` at the end |
| `DELETE /api/scans/:id`, `DELETE /api/scans` | | |
| `POST /api/scans/report` | `{type:"url"\|"phone",content}` | 3 distinct reporters -> indicator is blocklisted |
| `DELETE /api/me` | `{password}` | Deletes account and all data |
| `GET /health` | | |

`scan` is shaped for the existing Kotlin models: `type`/`threat` are lowercase (`"danger"`), `timestamp` is epoch ms, plus `id`, `content`, `details`, `score`.

### Plan rules (edit in `src/config.js`)

- **FREE**: 10 scans per rolling 24h (429 `daily_limit`), history of last 24h, no message scanning, no clipboard scans (403 `upgrade_required`).
- **PLUS**: unlimited, full history, message scanning, clipboard scans, extra typosquat detection.

Scanning before picking a plan returns 402 `plan_required`.

## How detection works

`src/scanner.js` is rule-based: URLs (IP hosts, `@` tricks, punycode, risky TLDs, shorteners, brand impersonation, sensitive keywords, no HTTPS), phone numbers (premium-rate, "one-ring" area codes, repeated digits), and messages (urgency, OTP/credential requests, gift cards/crypto, prize bait, delivery scams, embedded links). Scores map to SAFE (<25), WARNING (25-59), DANGER (60+). Plus a blocklist seeded with a few fake domains and fed by user reports.

This is a good v1, **not** a threat-intelligence feed. For real coverage, add Google Safe Browsing / PhishTank / VirusTotal inside `scanUrl()` and push a signal.

## Hooking up the Android app

1. Add `<uses-permission android:name="android.permission.INTERNET"/>` to `AndroidManifest.xml` (it's missing).
2. Base URL from the emulator is `http://10.0.2.2:3000`. For plain HTTP add `android:usesCleartextTraffic="true"` during development only; use HTTPS in release.
3. Add Retrofit/OkHttp + kotlinx.serialization (or Ktor), store the token in EncryptedSharedPreferences instead of the current `prism_logged_in` boolean, and replace the `delay`/`random()` blocks in `AppStateViewModel` with the calls above.
4. Handle `403 upgrade_required` / `429 daily_limit` by opening the existing subscription modal.

## Known gaps before a real launch

- `PUT /api/subscription` trusts the client. Verify Google Play Billing purchase tokens server-side before granting PLUS.
- No email verification or password reset (needs an email provider).
- Single SQLite file: fine for one instance; move to Postgres if you scale horizontally.
- Scan content is stored so history works; mention that in your privacy policy.
