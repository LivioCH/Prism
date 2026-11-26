process.env.NODE_ENV = 'test';
// FREE_DAILY_SCAN_LIMIT is deliberately NOT set: this is the default behaviour.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';

let server, base;
const fakeGoogle = { checkUrl: async (url) => ({ url, threatTypes: [] }) };
before(async () => {
  server = createApp(openDb(':memory:'), { linkChecker: fakeGoogle }).listen(0);
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
const newUser = async (email, plan) => {
  const s = await call('POST', '/api/auth/signup', { body: { name: 'U', email, password: 'secret1' } });
  await call('PUT', '/api/subscription', { token: s.json.token, body: { plan } });
  return s.json.token;
};

test('by default Free has no Google check at all', async () => {
  const token = await newUser('free@example.com', 'FREE');
  assert.equal((await call('GET', '/api/quota', { token })).json.quota.included, false);
  assert.equal((await call('POST', '/api/scans/webrisk', { token, body: { text: 'https://a.example.com' } })).status, 403);
});

test('Plus has the Google check with no daily limit', async () => {
  const token = await newUser('plus@example.com', 'PLUS');
  assert.equal((await call('GET', '/api/quota', { token })).json.quota.unlimited, true);
  for (let i = 0; i < 15; i++) {
    const r = await call('POST', '/api/scans/webrisk', { token, body: { text: `https://site${i}.example.com` } });
    assert.equal(r.status, 201, `check ${i + 1} must not be limited`);
  }
});
