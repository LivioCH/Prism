#!/usr/bin/env node
// Local admin tool for the Prism account database. Runs on your machine only (no HTTP endpoint).
//
//   npm run admin -- list                         all accounts with plan and scan counts
//   npm run admin -- show <email>                 one account + its latest scans
//   npm run admin -- reset-password <email> [new] set a new password (random one is generated if omitted)
//   npm run admin -- set-plan <email> FREE|PLUS
//   npm run admin -- create-user <email> <password> [FREE|PLUS] [name]   ordinary account, short password allowed
//   npm run admin -- delete <email>               deletes the account and all its data
//
// Passwords are bcrypt hashes and can never be read back; reset-password is the way to regain access.
// DATABASE_PATH is honoured, default ./data/prism.db. Stop the server first if you hit "database is locked".

import { openDb } from '../src/db.js';
import { existsSync } from 'node:fs';
import { randomBytes, randomUUID } from 'node:crypto';
import bcrypt from 'bcryptjs';

const path = process.env.DATABASE_PATH || './data/prism.db';
if (!existsSync(path)) {
  console.error(`Database not found at ${path}. Run from prism-backend/ or set DATABASE_PATH.`);
  process.exit(1);
}
const db = openDb(path); // also applies pending migrations (e.g. the is_admin column)

const [cmd, emailArg, extra, ...rest] = process.argv.slice(2);
const email = emailArg?.trim().toLowerCase();
const fmt = (ms) => new Date(ms).toLocaleString('id-ID');
const need = (cond, msg) => { if (!cond) { console.error(msg); process.exit(1); } };
const findUser = () => {
  need(email, 'Email is required.');
  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  need(u, `No account with email ${email}`);
  return u;
};

switch (cmd) {
  case 'list': {
    const rows = db.prepare(
      `SELECT u.name, u.email, u.plan, u.created_at,
              (SELECT COUNT(*) FROM scans s WHERE s.user_id = u.id) AS scans
       FROM users u ORDER BY u.created_at`
    ).all();
    if (!rows.length) { console.log('No accounts.'); break; }
    console.table(rows.map((r) => ({ name: r.name, email: r.email, plan: r.plan ?? '(none)', scans: r.scans, created: fmt(r.created_at) })));
    break;
  }
  case 'show': {
    const u = findUser();
    console.log({ id: u.id, name: u.name, email: u.email, plan: u.plan ?? '(none)', clipboardMonitoring: !!u.clipboard_monitoring, created: fmt(u.created_at) });
    const scans = db.prepare('SELECT type, threat, content, created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 10').all(u.id);
    console.table(scans.map((s) => ({ when: fmt(s.created_at), type: s.type, threat: s.threat, content: s.content.slice(0, 60) })));
    break;
  }
  case 'reset-password': {
    const u = findUser();
    const pw = extra ?? randomBytes(6).toString('base64url');
    need(pw.length >= 6, 'Password must be at least 6 characters.');
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(pw, 10), u.id);
    console.log(`Password for ${u.email} is now: ${pw}`);
    console.log('Existing login tokens stay valid until they expire.');
    break;
  }
  case 'set-plan': {
    const u = findUser();
    const plan = extra?.toUpperCase();
    need(plan === 'FREE' || plan === 'PLUS', 'Plan must be FREE or PLUS.');
    db.prepare('UPDATE users SET plan = ? WHERE id = ?').run(plan, u.id);
    console.log(`${u.email} is now on ${plan}.`);
    break;
  }
  case 'create-admin': {
    // Local tool, so it may use a short password that signup (min 6) would refuse. Dev use only.
    need(email, 'Email is required.');
    need(extra, 'Usage: create-admin <email> <password>');
    const hash = bcrypt.hashSync(extra, 10);
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) {
      db.prepare('UPDATE users SET is_admin = 1, password_hash = ? WHERE id = ?').run(hash, existing.id);
    } else {
      db.prepare('INSERT INTO users (id, name, email, password_hash, plan, is_admin, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)')
        .run(randomUUID(), 'Admin', email, hash, 'PLUS', Date.now());
    }
    console.log(`Admin account ready: ${email}`);
    break;
  }
  case 'create-user': {
    // Ordinary (non-admin) account. Local tool, so a short password that signup would refuse is fine. Dev use only.
    need(email, 'Email is required.');
    need(extra, 'Usage: create-user <email> <password> [FREE|PLUS] [name]');
    const plan = (rest[0] ?? 'FREE').toUpperCase();
    if (plan !== 'FREE' && plan !== 'PLUS') { console.error('Plan must be FREE or PLUS.'); process.exit(1); }
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) {
      console.error(`An account with ${email} already exists.`);
      process.exit(1);
    }
    db.prepare('INSERT INTO users (id, name, email, password_hash, plan, is_admin, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
      .run(randomUUID(), rest[1] ?? email.split('@')[0], email, bcrypt.hashSync(extra, 10), plan, Date.now());
    console.log(`Account ready: ${email} (${plan})`);
    break;
  }

  case 'delete': {
    const u = findUser();
    db.prepare('DELETE FROM users WHERE id = ?').run(u.id);
    console.log(`Deleted ${u.email} and all their scans/reports.`);
    break;
  }
  default:
    console.log('Usage: npm run admin -- <list | show <email> | reset-password <email> [new] | set-plan <email> FREE|PLUS | create-admin <email> <password> | create-user <email> <password> [FREE|PLUS] [name] | delete <email>>');
}
