process.env.NODE_ENV = 'test';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';
import { DetectorError } from '../src/webrisk.js';

const GOOD = 'AIza' + 'x'.repeat(35);
const BAD = 'AIza' + 'y'.repeat(35);
const OFFLINE = 'AIza' + 'z'.repeat(35);

// A stand-in for Google: accepts GOOD, rejects BAD (403), and cannot be reached with OFFLINE.
const makeDetector = ({ apiKey }) => ({
  checkUrl: async (url) => {
    if (apiKey === OFFLINE) throw new TypeError('fetch failed');
    if (apiKey !== GOOD) throw new DetectorError('Web Risk returned 403');
    return { url, threatTypes: url.includes('malware') ? ['MALWARE'] : [] };
  },
});

let server, base, db, admin, user;
const call = async (method, path, { token, body } = {}) => {
  const res = await fetch(base + path, {
    method,
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
};
const signup = (email) => call('POST', '/api/auth/signup', { body: { name: 'T', email, password: 'secret1' } });

before(async () => {
  db = openDb(':memory:');
  server = createApp(db, { makeDetector }).listen(0);   // no key anywhere: Google starts switched off
  base = `http://127.0.0.1:${server.address().port}`;
  admin = (await signup('boss@example.com')).json.token;
  db.prepare('UPDATE users SET is_admin = 1 WHERE email = ?').run('boss@example.com');
  user = (await signup('plain@example.com')).json.token;
  await call('PUT', '/api/subscription', { token: user, body: { plan: 'PLUS' } });   // the Google check is Plus only
});
after(() => server.close());

test('only an admin can see or change the Google key', async () => {
  assert.equal((await call('GET', '/api/admin/google-key')).status, 401);
  assert.equal((await call('GET', '/api/admin/google-key', { token: user })).status, 403);
  assert.equal((await call('PUT', '/api/admin/google-key', { token: user, body: { key: GOOD } })).status, 403);
  assert.equal((await call('DELETE', '/api/admin/google-key', { token: user })).status, 403);
});

test('with no key: status says not active and Google scans answer 503', async () => {
  const s = await call('GET', '/api/admin/google-key', { token: admin });
  assert.deepEqual(s.json.google, { active: false, source: 'none', hint: null });
  assert.equal((await call('GET', '/api/quota', { token: user })).json.googleEnabled, false);
  assert.equal((await call('POST', '/api/scans/webrisk', { token: user, body: { text: 'https://example.com' } })).status, 503);
});

test('a malformed key, a key Google rejects, and an unverifiable key are all refused and not saved', async () => {
  assert.equal((await call('PUT', '/api/admin/google-key', { token: admin, body: { key: 'short' } })).status, 400);
  const rejected = await call('PUT', '/api/admin/google-key', { token: admin, body: { key: BAD } });
  assert.equal(rejected.status, 422);
  assert.equal(rejected.json.error.code, 'key_rejected');
  assert.equal((await call('PUT', '/api/admin/google-key', { token: admin, body: { key: OFFLINE } })).status, 502);
  assert.equal((await call('GET', '/api/admin/google-key', { token: admin })).json.google.active, false);
});

test('a good key is saved, works at once without a restart, and is never sent back in full', async () => {
  const put = await call('PUT', '/api/admin/google-key', { token: admin, body: { key: `  ${GOOD}  ` } });
  assert.equal(put.status, 200);
  assert.deepEqual(put.json.google, { active: true, source: 'app', hint: 'AIza...xxxx' });
  assert.ok(!JSON.stringify(put.json).includes(GOOD), 'full key must not be returned');
  assert.ok(!JSON.stringify((await call('GET', '/api/admin/google-key', { token: admin })).json).includes(GOOD));

  assert.equal((await call('GET', '/api/quota', { token: user })).json.googleEnabled, true);
  const scan = await call('POST', '/api/scans/webrisk', { token: user, body: { text: 'http://bad.example/malware' } });
  assert.equal(scan.status, 201);
  assert.equal(scan.json.isDangerous, true, 'the saved key is really used for checks');
});

test('removing the key switches Google off again', async () => {
  const del = await call('DELETE', '/api/admin/google-key', { token: admin });
  assert.equal(del.json.google.active, false);
  assert.equal((await call('POST', '/api/scans/webrisk', { token: user, body: { text: 'https://example.com' } })).status, 503);
});
