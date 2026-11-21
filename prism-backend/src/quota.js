import { DAY_MS, PLANS } from './config.js';

/**
 * How many Premium (Google Web Risk) checks the user has left. It counts the same rows the daily
 * limit in routes/scans.js counts (the user's scans of the last rolling 24h), so what the app shows
 * always matches what the server enforces.
 *
 * Plus is unlimited: { unlimited: true, limit: null, remaining: null, resetsAt: null }.
 * resetsAt (epoch ms) is when the oldest counted scan leaves the 24h window, freeing one check.
 */
export function googleQuota(db, user, now = Date.now()) {
  const limit = PLANS[user.plan ?? 'FREE'].dailyScanLimit;
  if (limit === Infinity) return { unlimited: true, limit: null, used: 0, remaining: null, resetsAt: null };
  const row = db
    .prepare('SELECT COUNT(*) AS c, MIN(created_at) AS oldest FROM scans WHERE user_id = ? AND created_at > ?')
    .get(user.id, now - DAY_MS);
  return {
    unlimited: false,
    limit,
    used: row.c,
    remaining: Math.max(0, limit - row.c),
    resetsAt: row.c > 0 ? row.oldest + DAY_MS : null,
  };
}
