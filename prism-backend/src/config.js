const isProd = process.env.NODE_ENV === 'production';

if (isProd && (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'change-me')) {
  throw new Error('JWT_SECRET must be set to a strong random value in production');
}

export const config = {
  port: Number(process.env.PORT || 3000),
  jwtSecret: process.env.JWT_SECRET || 'dev-only-secret-change-me',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '30d',
  databasePath: process.env.DATABASE_PATH || './data/prism.db',
  // Google Cloud Web Risk link check (POST /api/scans/webrisk). Without a key that route answers 503.
  webRiskApiKey: process.env.WEB_RISK_API_KEY || '',
};

// Daily scan limit of the Free plan. UNLIMITED by default (Free gets the Premium/Google check too).
// To bring the old limit back, set FREE_DAILY_SCAN_LIMIT=10 in the environment: the limit code,
// 429 daily_limit and GET /api/quota all still work.
const freeLimit = Number(process.env.FREE_DAILY_SCAN_LIMIT);

// Mirrors the plan cards in the app (FREE vs PLUS $4.99/month).
export const PLANS = {
  FREE: {
    dailyScanLimit: Number.isFinite(freeLimit) && freeLimit > 0 ? freeLimit : Infinity,
    historyWindowMs: 24 * 3600_000, // "Scan history (last 24 hours)"
    clipboardScan: false,        // "Real-time clipboard monitoring" is Plus
    messageScan: false,          // Free = "Basic URL & phone scanning"
    advancedDetection: false,    // "Advanced threat detection" is Plus
  },
  PLUS: {
    dailyScanLimit: Infinity,    // "Unlimited scans"
    historyWindowMs: Infinity,   // "Complete scan history"
    clipboardScan: true,
    messageScan: true,
    advancedDetection: true,
  },
};

export const DAY_MS = 24 * 3600_000;
