import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { DAY_MS, PLANS } from '../config.js';
import { HttpError } from '../errors.js';
import { scan, normalizeUrl, registrableDomain, normalizePhone } from '../scanner.js';
import { extractLinks, threatLabel } from '../webrisk.js';
import { publicScan } from '../serializers.js';
import { googleQuota } from '../quota.js';

const scanSchema = z.object({
  type: z.string().transform((s) => s.toUpperCase()).pipe(z.enum(['URL', 'PHONE', 'MESSAGE'])),
  content: z.string().trim().min(1, 'Nothing to scan').max(4000),
  source: z.enum(['manual', 'clipboard']).default('manual'),
});
const reportSchema = z.object({
  type: z.string().transform((s) => s.toUpperCase()).pipe(z.enum(['URL', 'PHONE'])),
  content: z.string().trim().min(1).max(2000),
});
const webRiskSchema = z.object({
  text: z.string().trim().min(1, 'Paste a link or a message with links').max(4000),
});
const listSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  before: z.coerce.number().int().optional(), // epoch-ms cursor: pass the last item's timestamp
});

// getWebRisk() returns the Google link checker, or null while no API key is set.
export function scanRoutes(db, getWebRisk = () => null) {
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

  // Google Cloud Web Risk: checks every link in a message (or a single link) against Google's lists
  // of phishing, malware and unwanted-software sites. A failed API call is an error (502), never "safe".
  r.post('/webrisk', async (req, res, next) => {
    try {
      const { text } = webRiskSchema.parse(req.body);
      const user = req.user;
      if (!user.plan) throw new HttpError(402, 'plan_required', 'Choose a plan to start scanning');
      const plan = PLANS[user.plan];
      if (!plan.googleCheck) {
        throw new HttpError(403, 'upgrade_required', 'The Google check is a Prism Plus feature', { feature: 'google_check' });
      }
      const webRisk = getWebRisk();
      if (!webRisk) throw new HttpError(503, 'webrisk_unavailable', 'Google link check is not set up on the server (no API key yet)');

      const links = extractLinks(text);
      if (!links.length) throw new HttpError(400, 'no_links', 'No links found. Google Web Risk only checks links');

      const now = Date.now();
      if (plan.dailyScanLimit !== Infinity) {
        const { c } = db.prepare('SELECT COUNT(*) AS c FROM scans WHERE user_id = ? AND created_at > ?').get(user.id, now - DAY_MS);
        if (c >= plan.dailyScanLimit) {
          // resetsAt tells the app when the next Premium check frees up
          throw new HttpError(429, 'daily_limit', `Free plan is limited to ${plan.dailyScanLimit} scans per day`, { limit: plan.dailyScanLimit, feature: 'unlimited_scans', resetsAt: googleQuota(db, user, now).resetsAt });
        }
      }

      let results;
      try {
        results = await Promise.all(links.map((l) => webRisk.checkUrl(l)));
      } catch (e) {
        console.error('Web Risk check failed:', e.message);
        throw new HttpError(502, 'webrisk_failed', 'Could not reach Google Web Risk, try again later');
      }
      results = results.map((x) => ({ ...x, threats: x.threatTypes.map(threatLabel) }));

      const flagged = results.filter((x) => x.threatTypes.length);
      const threat = flagged.length ? 'DANGER' : 'SAFE';
      const details = flagged.length
        ? `Google lists ${new URL(flagged[0].url).hostname} as a ${flagged[0].threats.join(' and ')} site`
        : `${links.length === 1 ? 'This link is not' : `None of the ${links.length} links is`} on Google's list of dangerous sites`;
      const signals = results.map((x) => ({
        id: 'webrisk', weight: x.threatTypes.length ? 100 : 0,
        text: `${x.url}: ${x.threatTypes.length ? x.threats.join(', ') : 'not listed'}`,
      }));
      const type = /\s/.test(text) ? 'MESSAGE' : 'URL';

      const id = randomUUID();
      db.prepare(
        `INSERT INTO scans (id, user_id, type, content, threat, details, score, signals, source, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'webrisk', ?)`
      ).run(id, user.id, type, text, threat, details, flagged.length ? 100 : 0, JSON.stringify(signals), now);

      res.status(201).json({
        scan: publicScan(db.prepare('SELECT * FROM scans WHERE id = ?').get(id)),
        isDangerous: flagged.length > 0,
        results,
        quota: googleQuota(db, user),   // what is left after this check, so the app needs no extra request
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
