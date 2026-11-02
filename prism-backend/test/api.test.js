process.env.NODE_ENV = 'test';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';

let server, base, db;
before(async () => {
  db = openDb(':memory:');
  server = createApp(db).listen(0);
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const call = async (method, path, { token, body } = {}) => {
  const res = await fetch(base + path, {
    method,
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
};
let n = 0;
const newUser = async (plan) => {
  const email = `u${++n}@example.com`;
  const s = await call('POST', '/api/auth/signup', { body: { name: 'Test', email, password: 'secret1' } });
  assert.equal(s.status, 201);
  if (plan) await call('PUT', '/api/subscription', { token: s.json.token, body: { plan } });
  return { token: s.json.token, email };
};

test('signup validates input and rejects duplicates', async () => {
  const bad = await call('POST', '/api/auth/signup', { body: { name: 'A', email: 'nope', password: '123' } });
  assert.equal(bad.status, 400);
  const { email } = await newUser();
  const dup = await call('POST', '/api/auth/signup', { body: { name: 'B', email: email.toUpperCase(), password: 'secret1' } });
  assert.equal(dup.status, 409);
});

test('login works, wrong password is rejected, plan starts null', async () => {
  const { email } = await newUser();
  const ok = await call('POST', '/api/auth/login', { body: { email, password: 'secret1' } });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.user.plan, null);
  assert.equal(ok.json.user.clipboardMonitoring, true);
  assert.equal((await call('POST', '/api/auth/login', { body: { email, password: 'wrong' } })).status, 401);
  assert.equal((await call('POST', '/api/auth/login', { body: { email: 'ghost@x.com', password: 'secret1' } })).status, 401);
});

test('protected routes need a valid token', async () => {
  assert.equal((await call('GET', '/api/me')).status, 401);
  assert.equal((await call('GET', '/api/me', { token: 'garbage' })).status, 401);
});

test('cannot scan before choosing a plan', async () => {
  const { token } = await newUser();
  const r = await call('POST', '/api/scans', { token, body: { type: 'url', content: 'https://example.com' } });
  assert.equal(r.status, 402);
});

test('blocklisted URL is DANGER, google is SAFE; response shape matches app models', async () => {
  const { token } = await newUser('FREE');
  const bad = await call('POST', '/api/scans', { token, body: { type: 'url', content: 'https://secure-bank-login.com' } });
  assert.equal(bad.status, 201);
  assert.equal(bad.json.scan.threat, 'danger');
  assert.equal(bad.json.scan.type, 'url');
  assert.equal(bad.json.showAlert, true);
  assert.equal(typeof bad.json.scan.timestamp, 'number');
  const good = await call('POST', '/api/scans', { token, body: { type: 'URL', content: 'https://www.google.com' } });
  assert.equal(good.json.scan.threat, 'safe');
  assert.equal(good.json.showAlert, false);
});

test('free plan: 10 scans/day then 429; message + clipboard gated', async () => {
  const { token } = await newUser('FREE');
  for (let i = 0; i < 10; i++) {
    assert.equal((await call('POST', '/api/scans', { token, body: { type: 'phone', content: `+1 555 123 45${10 + i}` } })).status, 201);
  }
  const over = await call('POST', '/api/scans', { token, body: { type: 'phone', content: '+1 555 000 1111' } });
  assert.equal(over.status, 429);
  assert.equal(over.json.error.code, 'daily_limit');

  const other = await newUser('FREE');
  const msg = await call('POST', '/api/scans', { token: other.token, body: { type: 'message', content: 'hi' } });
  assert.equal(msg.status, 403);
  const clip = await call('POST', '/api/scans', { token: other.token, body: { type: 'url', content: 'https://a.com', source: 'clipboard' } });
  assert.equal(clip.status, 403);
});

test('plus plan: unlimited, message scan flags scam text, clipboard honors toggle', async () => {
  const { token } = await newUser('PLUS');
  const m = await call('POST', '/api/scans', {
    token,
    body: { type: 'message', content: 'URGENT your account is suspended. Reply with your OTP or buy a gift card http://bit.ly/x1' },
  });
  assert.equal(m.json.scan.threat, 'danger');
  const clip = await call('POST', '/api/scans', { token, body: { type: 'url', content: 'https://example.org', source: 'clipboard' } });
  assert.equal(clip.status, 201);
  await call('PATCH', '/api/settings', { token, body: { clipboardMonitoring: false } });
  const off = await call('POST', '/api/scans', { token, body: { type: 'url', content: 'https://example.org', source: 'clipboard' } });
  assert.equal(off.status, 409);
});

test('history is per-user, newest first, paginates; free plan hides >24h', async () => {
  const a = await newUser('FREE');
  const b = await newUser('FREE');
  for (const u of ['https://a1.com', 'https://a2.com', 'https://a3.com']) {
    await call('POST', '/api/scans', { token: a.token, body: { type: 'url', content: u } });
  }
  await call('POST', '/api/scans', { token: b.token, body: { type: 'url', content: 'https://b.com' } });
  const page1 = await call('GET', '/api/scans?limit=2', { token: a.token });
  assert.equal(page1.json.scans.length, 2);
  assert.equal(page1.json.scans[0].content, 'https://a3.com');
  assert.ok(page1.json.nextBefore);
  const all = await call('GET', '/api/scans', { token: a.token });
  assert.equal(all.json.scans.length, 3);

  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(a.email);
  db.prepare('UPDATE scans SET created_at = ? WHERE user_id = ? AND content = ?').run(Date.now() - 48 * 3600_000, user.id, 'https://a1.com');
  assert.equal((await call('GET', '/api/scans', { token: a.token })).json.scans.length, 2);
});

test('stats reflect scans and privacy score drops with threats', async () => {
  const { token } = await newUser('PLUS');
  const before = await call('GET', '/api/stats', { token });
  assert.deepEqual([before.json.scansToday, before.json.privacyScore], [0, 100]);
  await call('POST', '/api/scans', { token, body: { type: 'url', content: 'https://secure-bank-login.com' } });
  await call('POST', '/api/scans', { token, body: { type: 'url', content: 'https://www.wikipedia.org' } });
  const s = await call('GET', '/api/stats', { token });
  assert.equal(s.json.scansToday, 2);
  assert.equal(s.json.threatsBlocked, 1);
  assert.equal(s.json.privacyScore, 95);
});

test('community reports: 3 distinct users blocklist a domain', async () => {
  const users = [await newUser('FREE'), await newUser('FREE'), await newUser('FREE')];
  const probe = await newUser('FREE');
  const target = 'https://fresh-scam-site.net/x';
  const first = await call('POST', '/api/scans', { token: probe.token, body: { type: 'url', content: target } });
  assert.equal(first.json.scan.threat, 'safe');
  for (const u of users) assert.equal((await call('POST', '/api/scans/report', { token: u.token, body: { type: 'url', content: target } })).status, 202);
  await call('POST', '/api/scans/report', { token: users[0].token, body: { type: 'url', content: target } }); // duplicate ignored
  const after = await call('POST', '/api/scans', { token: probe.token, body: { type: 'url', content: target } });
  assert.equal(after.json.scan.threat, 'danger');
});

test('delete scan and delete account', async () => {
  const { token } = await newUser('FREE');
  const s = await call('POST', '/api/scans', { token, body: { type: 'url', content: 'https://x.com' } });
  assert.equal((await call('DELETE', `/api/scans/${s.json.scan.id}`, { token })).status, 204);
  assert.equal((await call('DELETE', `/api/scans/${s.json.scan.id}`, { token })).status, 404);
  assert.equal((await call('DELETE', '/api/me', { token, body: { password: 'bad' } })).status, 403);
  assert.equal((await call('DELETE', '/api/me', { token, body: { password: 'secret1' } })).status, 204);
  assert.equal((await call('GET', '/api/me', { token })).status, 401);
});
