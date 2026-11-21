process.env.NODE_ENV = 'test';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';

let server, base;
before(() => {
  server = createApp(openDb(':memory:')).listen(0);
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

test('change password: wrong current is refused, right one works, old password stops working', async () => {
  const s = await call('POST', '/api/auth/signup', { body: { name: 'P', email: 'pw@example.com', password: 'oldpass1' } });
  const token = s.json.token;

  const bad = await call('PUT', '/api/me/password', { token, body: { currentPassword: 'nope', newPassword: 'newpass1' } });
  assert.equal(bad.status, 403);

  const short = await call('PUT', '/api/me/password', { token, body: { currentPassword: 'oldpass1', newPassword: '123' } });
  assert.equal(short.status, 400);

  const ok = await call('PUT', '/api/me/password', { token, body: { currentPassword: 'oldpass1', newPassword: 'newpass1' } });
  assert.equal(ok.status, 204);

  assert.equal((await call('POST', '/api/auth/login', { body: { email: 'pw@example.com', password: 'oldpass1' } })).status, 401);
  assert.equal((await call('POST', '/api/auth/login', { body: { email: 'pw@example.com', password: 'newpass1' } })).status, 200);
});

test('change password needs a login', async () => {
  assert.equal((await call('PUT', '/api/me/password', { body: { currentPassword: 'a', newPassword: 'bbbbbb' } })).status, 401);
});
