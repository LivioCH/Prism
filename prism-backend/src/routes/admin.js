import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { HttpError } from '../errors.js';
import { publicUser } from '../serializers.js';

const planSchema = z.object({ plan: z.enum(['FREE', 'PLUS']) });

// Admin-only (guarded in app.js). Passwords are bcrypt hashes and are never returned.
const passwordSchema = z.object({ newPassword: z.string().min(6, 'Password must be at least 6 characters').max(200) });
const keySchema =z.object({ key: z.string().min(1).max(300) });

export function adminRoutes(db, google) {
  const r = Router();

  // Google API key: is it set, and where from. The key itself is never returned, only a masked hint.
  r.get('/google-key', (_req, res) => res.json({ google: google.status() }));

  // Saved only after Google accepts the key; it is used by the very next scan, no restart needed.
  r.put('/google-key', async (req, res, next) => {
    try {
      const { key } = keySchema.parse(req.body);
      res.json({ google: await google.setKey(key) });
    } catch (e) { next(e); }
  });

  r.delete('/google-key', (_req, res) => res.json({ google: google.clear() }));

  // All accounts in the database, with how many scans each has.
  r.get('/users', (_req, res) => {
    const rows = db.prepare(
      `SELECT u.*, (SELECT COUNT(*) FROM scans s WHERE s.user_id = u.id) AS scan_count
       FROM users u ORDER BY u.created_at`
    ).all();
    res.json({ users: rows.map((u) => ({ ...publicUser(u), scanCount: u.scan_count })) });
  });

  // Set a new password for any account (forgotten passwords). Passwords can never be read back, only replaced.
  // Same length rule as signup. The user's existing login tokens keep working until they expire.
  r.put('/users/:id/password', async (req, res, next) => {
    try {
      const { newPassword } = passwordSchema.parse(req.body);
      const hash = await bcrypt.hash(newPassword, 10);
      const info = db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.params.id);
      if (!info.changes) throw new HttpError(404, 'not_found', 'User not found');
      res.status(204).end();
    } catch (e) { next(e); }
  });

  // Change anyone's plan (an admin changes their own via PUT /api/subscription as usual).
  r.put('/users/:id/plan', (req, res, next) => {
    try {
      const { plan } = planSchema.parse(req.body);
      const info = db.prepare('UPDATE users SET plan = ? WHERE id = ?').run(plan, req.params.id);
      if (!info.changes) throw new HttpError(404, 'not_found', 'User not found');
      res.json({ user: publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id)) });
    } catch (e) { next(e); }
  });

  return r;
}
