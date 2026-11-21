process.env.NODE_ENV = 'test';
import './free-limit-10.js';   // the limit is off by default: this file tests it
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';

let server, base, db;
const fakeGoogle = { checkUrl: async (url) => ({ url, threatTypes: [] }) };
before(async () => {
  db = openDb(':memory:');
  server = createApp(db, { linkChecker: fakeGoogle }).listen(0);
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
  const s = await call('POST', '/api/auth/signup', { body: { name: 'Q', email: `q${++n}@example.com`, password: 'secret1' } });
  await call('PUT', '/api/subscription', { token: s.json.token, body: { plan } });
  return s.json.token;
};

test('a Free user starts with 10 Premium checks and each Google check uses one', async () => {
  const token = await newUser('FREE');
  const q0 = (await call('GET', '/api/quota', { token })).json.quota;
  assert.deepEqual(q0, { unlimited: false, limit: 10, used: 0, remaining: 10, resetsAt: null });

  const r = await call('POST', '/api/scans/webrisk', { token, body: { text: 'https://example.com' } });
  assert.equal(r.status, 201);
  assert.equal(r.json.quota.remaining, 9);
  assert.equal(r.json.quota.used, 1);
  assert.ok(r.json.quota.resetsAt > Date.now());

  assert.equal((await call('GET', '/api/quota', { token })).json.quota.remaining, 9, 'GET /api/quota agrees');
});

test('when the 10 are used up the server answers 429 with resetsAt, and quota says 0 left', async () => {
  const token = await newUser('FREE');
  for (let i = 0; i < 10; i++) {
    assert.equal((await call('POST', '/api/scans/webrisk', { token, body: { text: `https://site${i}.example.com` } })).status, 201);
  }
  assert.equal((await call('GET', '/api/quota', { token })).json.quota.remaining, 0);

  const over = await call('POST', '/api/scans/webrisk', { token, body: { text: 'https://one-more.example.com' } });
  assert.equal(over.status, 429);
  assert.equal(over.json.error.code, 'daily_limit');
  assert.equal(over.json.error.limit, 10);
  assert.ok(over.json.error.resetsAt > Date.now(), 'tells the app when a check frees up');
});

test('Plus is unlimited', async () => {
  const token = await newUser('PLUS');
  const q = (await call('GET', '/api/quota', { token })).json.quota;
  assert.equal(q.unlimited, true);
  assert.equal(q.remaining, null);
  const r = await call('POST', '/api/scans/webrisk', { token, body: { text: 'https://example.com' } });
  assert.equal(r.json.quota.unlimited, true);
});

test('GET /api/quota says whether the Google check is switched on', async () => {
  const token = await newUser('FREE');
  assert.equal((await call('GET', '/api/quota', { token })).json.googleEnabled, true, 'a link checker is configured here');
  const bare = createApp(openDb(':memory:')).listen(0);   // no key, no checker
  try {
    const url = `http://127.0.0.1:${bare.address().port}`;
    const s = await (await fetch(url + '/api/auth/signup', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: 'N', email: 'n@example.com', password: 'secret1' }) })).json();
    const q = await (await fetch(url + '/api/quota', { headers: { authorization: `Bearer ${s.token}` } })).json();
    assert.equal(q.googleEnabled, false);
  } finally { bare.close(); }
});

test('quota needs a login', async () => {
  assert.equal((await call('GET', '/api/quota')).status, 401);
});
