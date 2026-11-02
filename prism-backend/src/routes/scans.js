import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { DAY_MS, PLANS } from '../config.js';
import { HttpError } from '../errors.js';
import { scan, normalizeUrl, registrableDomain, normalizePhone } from '../scanner.js';
import { publicScan } from '../serializers.js';

const scanSchema = z.object({
  type: z.string().transform((s) => s.toUpperCase()).pipe(z.enum(['URL', 'PHONE', 'MESSAGE'])),
  content: z.string().trim().min(1, 'Nothing to scan').max(4000),
  source: z.enum(['manual', 'clipboard']).default('manual'),
});
const reportSchema = z.object({
  type: z.string().transform((s) => s.toUpperCase()).pipe(z.enum(['URL', 'PHONE'])),
  content: z.string().trim().min(1).max(2000),
});
const listSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  before: z.coerce.number().int().optional(), // epoch-ms cursor: pass the last item's timestamp
});

export function scanRoutes(db) {
  const r = Router();

  const loadBlocklist = () =>
    new Set(db.prepare('SELECT indicator FROM blocklist WHERE reports >= 3').all().map((x) => x.indicator));

  r.post('/', (req, res, next) => {
    try {
      const { type, content, source } = scanSchema.parse(req.body);
      const user = req.user;
      if (!user.plan) throw new HttpError(402, 'plan_required', 'Choose a plan to start scanning');
      const plan = PLANS[user.plan];

      if (type === 'MESSAGE' && !plan.messageScan) {
        throw new HttpError(403, 'upgrade_required', 'Message scanning is a Prism Plus feature', { feature: 'message_scan' });
      }
      if (source === 'clipboard' && !plan.clipboardScan) {
        throw new HttpError(403, 'upgrade_required', 'Clipboard monitoring is a Prism Plus feature', { feature: 'clipboard' });
      }
      if (source === 'clipboard' && !user.clipboard_monitoring) {
        throw new HttpError(409, 'monitoring_disabled', 'Clipboard monitoring is turned off');
      }

      const now = Date.now();
      if (plan.dailyScanLimit !== Infinity) {
        const { c } = db.prepare('SELECT COUNT(*) AS c FROM scans WHERE user_id = ? AND created_at > ?').get(user.id, now - DAY_MS);
        if (c >= plan.dailyScanLimit) {
          throw new HttpError(429, 'daily_limit', `Free plan is limited to ${plan.dailyScanLimit} scans per day`, { limit: plan.dailyScanLimit, feature: 'unlimited_scans' });
        }
      }

      const result = scan(type, content, { blocklist: loadBlocklist(), advanced: plan.advancedDetection });
      const id = randomUUID();
      db.prepare(
        `INSERT INTO scans (id, user_id, type, content, threat, details, score, signals, source, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(id, user.id, type, content, result.threat, result.details, result.score, JSON.stringify(result.signals), source, now);

      const row = db.prepare('SELECT * FROM scans WHERE id = ?').get(id);
      res.status(201).json({
        scan: publicScan(row),
        signals: result.signals.map((s) => s.text),
        // Mirrors the app: DANGER/WARNING open the alert dialog, SAFE shows the "All Clear" toast.
        showAlert: result.threat !== 'SAFE',
      });
    } catch (e) { next(e); }
  });

  r.get('/', (req, res, next) => {
    try {
      const { limit, before } = listSchema.parse(req.query);
      const plan = PLANS[req.user.plan ?? 'FREE'];
      const floor = plan.historyWindowMs === Infinity ? 0 : Date.now() - plan.historyWindowMs;
      const rows = db.prepare(
        `SELECT * FROM scans WHERE user_id = ? AND created_at > ? AND created_at < ?
         ORDER BY created_at DESC LIMIT ?`
      ).all(req.user.id, floor, before ?? Number.MAX_SAFE_INTEGER, limit);
      res.json({
        scans: rows.map(publicScan),
        nextBefore: rows.length === limit ? rows[rows.length - 1].created_at : null,
      });
    } catch (e) { next(e); }
  });

  r.delete('/', (req, res) => {
    db.prepare('DELETE FROM scans WHERE user_id = ?').run(req.user.id);
    res.status(204).end();
  });

  r.delete('/:id', (req, res) => {
    const info = db.prepare('DELETE FROM scans WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
    if (!info.changes) throw new HttpError(404, 'not_found', 'Scan not found');
    res.status(204).end();
  });

  // Community reports: once an indicator has 3 distinct reporters it joins the blocklist.
  r.post('/report', (req, res, next) => {
    try {
      const { type, content } = reportSchema.parse(req.body);
      let indicator;
      if (type === 'URL') {
        const p = normalizeUrl(content);
        if (!p) throw new HttpError(400, 'validation_error', 'Not a valid URL');
        indicator = registrableDomain(p.url.hostname.toLowerCase());
      } else {
        indicator = normalizePhone(content).digits;
        if (indicator.length < 7 || indicator.length > 15) throw new HttpError(400, 'validation_error', 'Not a valid phone number');
      }
      const ins = db.prepare(
        'INSERT OR IGNORE INTO reports (id, user_id, type, indicator, created_at) VALUES (?, ?, ?, ?, ?)'
      ).run(randomUUID(), req.user.id, type, indicator, Date.now());
      if (ins.changes) {
        db.prepare(
          `INSERT INTO blocklist (indicator, type, reports, created_at) VALUES (?, ?, 1, ?)
           ON CONFLICT(indicator, type) DO UPDATE SET reports = reports + 1`
        ).run(indicator, type, Date.now());
      }
      res.status(202).json({ status: 'received' });
    } catch (e) { next(e); }
  });

  return r;
}
