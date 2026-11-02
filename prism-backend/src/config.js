const isProd = process.env.NODE_ENV === 'production';

if (isProd && (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'change-me')) {
  throw new Error('JWT_SECRET must be set to a strong random value in production');
}

export const config = {
  port: Number(process.env.PORT || 3000),
  jwtSecret: process.env.JWT_SECRET || 'dev-only-secret-change-me',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '30d',
  databasePath: process.env.DATABASE_PATH || './data/prism.db',
};

// Mirrors the plan cards in the app (FREE vs PLUS $4.99/month).
export const PLANS = {
  FREE: {
    dailyScanLimit: 10,          // "10 scans per day"
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
