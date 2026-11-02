import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { DAY_MS } from '../config.js';
import { HttpError } from '../errors.js';
import { publicUser } from '../serializers.js';

const planSchema = z.object({ plan: z.enum(['FREE', 'PLUS']) });
const settingsSchema = z.object({ clipboardMonitoring: z.boolean() });
const deleteSchema = z.object({ password: z.string().min(1) });

export function meRoutes(db) {
  const r = Router();
  const getUser = db.prepare('SELECT * FROM users WHERE id = ?');

  r.get('/me', (req, res) => res.json({ user: publicUser(req.user) }));

  // NOTE: no payment processing yet. PLUS is granted on request; wire this to
  // Google Play Billing receipt verification before charging real money.
  r.put('/subscription', (req, res, next) => {
    try {
      const { plan } = planSchema.parse(req.body);
      db.prepare('UPDATE users SET plan = ? WHERE id = ?').run(plan, req.user.id);
      res.json({ user: publicUser(getUser.get(req.user.id)) });
    } catch (e) { next(e); }
  });

  r.patch('/settings', (req, res, next) => {
    try {
      const { clipboardMonitoring } = settingsSchema.parse(req.body);
      db.prepare('UPDATE users SET clipboard_monitoring = ? WHERE id = ?').run(clipboardMonitoring ? 1 : 0, req.user.id);
      res.json({ user: publicUser(getUser.get(req.user.id)) });
    } catch (e) { next(e); }
  });

  // Dashboard header: scansToday / threatsBlocked / privacyAlerts / privacyScore
  r.get('/stats', (req, res) => {
    const now = Date.now();
    const row = db.prepare(`
      SELECT
        SUM(created_at > ?1) AS scans_today,
        SUM(created_at > ?1 AND threat = 'DANGER') AS threats_today,
        SUM(created_at > ?1 AND threat = 'WARNING') AS warnings_today,
        SUM(threat = 'DANGER') AS threats_total,
        SUM(threat = 'WARNING') AS warnings_total,
        SUM(created_at > ?2 AND threat = 'DANGER') AS danger_30d,
        SUM(created_at > ?2 AND threat = 'WARNING') AS warning_30d
      FROM scans WHERE user_id = ?3
    `).get(now - DAY_MS, now - 30 * DAY_MS, req.user.id);
    const n = (v) => Number(v ?? 0);

    // Score: start at 100, lose points for recent risky scans the user ran into,
    // small penalty for having monitoring off. Clamped to 0-100.
    let score = 100 - n(row.danger_30d) * 5 - n(row.warning_30d) * 2;
    if (!req.user.clipboard_monitoring) score -= 10;
    score = Math.max(0, Math.min(100, score));

    res.json({
      scansToday: n(row.scans_today),
      threatsBlocked: n(row.threats_total),
      privacyAlerts: n(row.warnings_total),
      privacyScore: score,
      plan: req.user.plan,
    });
  });

  r.delete('/me', async (req, res, next) => {
    try {
      const { password } = deleteSchema.parse(req.body);
      if (!(await bcrypt.compare(password, req.user.password_hash))) {
        throw new HttpError(403, 'invalid_credentials', 'Incorrect password');
      }
      db.prepare('DELETE FROM users WHERE id = ?').run(req.user.id);
      res.status(204).end();
    } catch (e) { next(e); }
  });

  return r;
}
