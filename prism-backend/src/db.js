import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export function openDb(path) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      plan TEXT CHECK (plan IN ('FREE','PLUS')),      -- NULL until the user picks one
      clipboard_monitoring INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL CHECK (type IN ('URL','PHONE','MESSAGE')),
      content TEXT NOT NULL,
      threat TEXT NOT NULL CHECK (threat IN ('SAFE','WARNING','DANGER')),
      details TEXT NOT NULL,
      score INTEGER NOT NULL,
      signals TEXT NOT NULL,                           -- JSON array
      source TEXT NOT NULL DEFAULT 'manual',           -- manual | clipboard
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_scans_user_time ON scans(user_id, created_at DESC);

    -- Known-bad indicators (normalized host or phone digits). Grows from user reports.
    CREATE TABLE IF NOT EXISTS blocklist (
      indicator TEXT NOT NULL,
      type TEXT NOT NULL CHECK (type IN ('URL','PHONE')),
      reports INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (indicator, type)
    );

    CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
      type TEXT NOT NULL,
      indicator TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      UNIQUE (user_id, type, indicator)
    );
  `);

  // Seed a few obviously fake indicators so the blocklist path works out of the box.
  const seed = db.prepare(
    `INSERT OR IGNORE INTO blocklist (indicator, type, reports, created_at) VALUES (?, ?, 25, ?)`
  );
  const now = Date.now();
  for (const host of ['secure-bank-login.com', 'paypa1-verify.com', 'appleid-support-locked.com']) {
    seed.run(host, 'URL', now);
  }
  return db;
}
