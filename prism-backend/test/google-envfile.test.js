process.env.NODE_ENV = 'test';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/db.js';
import { createGoogleLink } from '../src/googleLink.js';

const GOOD = 'AIza' + 'x'.repeat(35);
const OTHER = 'AIza' + 'w'.repeat(35);
const makeDetector = () => ({ checkUrl: async () => ({ threatTypes: [] }) });
const tmp = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'prism-env-')), '.env');

test('a key saved from the app is written into .env and nowhere in the database', async () => {
  const file = tmp();
  fs.writeFileSync(file, 'PORT=3000\nWEB_RISK_API_KEY=\nJWT_SECRET=keep-me\n');
  const db = openDb(':memory:');
  const g = createGoogleLink(db, { envFile: file, envKey: '', makeDetector });
  assert.equal(g.status().active, false);
  assert.deepEqual(await g.setKey(GOOD), { active: true, source: 'env', hint: 'AIza...xxxx' });
  assert.equal(fs.readFileSync(file, 'utf8'), `PORT=3000\nWEB_RISK_API_KEY=${GOOD}\nJWT_SECRET=keep-me\n`);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM settings WHERE key = 'web_risk_api_key'").get().n, 0);
});

test('editing .env by hand is seen at once, and clearing it switches Google off', () => {
  const file = tmp();
  fs.writeFileSync(file, `WEB_RISK_API_KEY=${GOOD}\n`);
  const g = createGoogleLink(openDb(':memory:'), { envFile: file, envKey: GOOD, makeDetector });
  assert.equal(g.status().active, true);
  fs.writeFileSync(file, `WEB_RISK_API_KEY=${OTHER}\n`);
  assert.equal(g.status().hint, 'AIza...wwww');
  assert.equal(g.clear().active, false, 'an empty line in .env wins over the key present at startup');
  assert.equal(fs.readFileSync(file, 'utf8'), 'WEB_RISK_API_KEY=\n');
});

test('a missing .env is created, and an old key in prism.db is moved into it', () => {
  const file = tmp();
  const db = openDb(':memory:');
  db.prepare("INSERT INTO settings (key, value) VALUES ('web_risk_api_key', ?)").run(GOOD);
  const g = createGoogleLink(db, { envFile: file, envKey: '', makeDetector });
  assert.equal(g.status().active, true);
  assert.equal(fs.readFileSync(file, 'utf8'), `WEB_RISK_API_KEY=${GOOD}\n`);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM settings').get().n, 0);
});
