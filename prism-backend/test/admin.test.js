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
const signup = (email) => call('POST', '/api/auth/signup', { body: { name: 'T', email, password: 'secret1' } });

test('admin endpoints reject anonymous and regular users', async () => {
  assert.equal((await call('GET', '/api/admin/users')).status, 401);
  const u = await signup('regular@example.com');
  assert.equal((await call('GET', '/api/admin/users', { token: u.json.token })).status, 403);
  assert.equal((await call('PUT', `/api/admin/users/${u.json.user.id}/plan`, { token: u.json.token, body: { plan: 'PLUS' } })).status, 403);
});

test('admin lists all accounts without password hashes and can change any plan', async () => {
  const u = await signup('victim@example.com');
  const a = await signup('boss@example.com');
  db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(a.json.user.id);

  const list = await call('GET', '/api/admin/users', { token: a.json.token });
  assert.equal(list.status, 200);
  assert.ok(list.json.users.some((x) => x.email === 'victim@example.com'));
  assert.ok(!JSON.stringify(list.json).includes('password'));

  const set = await call('PUT', `/api/admin/users/${u.json.user.id}/plan`, { token: a.json.token, body: { plan: 'PLUS' } });
  assert.equal(set.status, 200);
  assert.equal(set.json.user.plan, 'PLUS');

  const own = await call('PUT', '/api/subscription', { token: a.json.token, body: { plan: 'FREE' } });
  assert.equal(own.json.user.plan, 'FREE');
  assert.equal(own.json.user.isAdmin, true);

  assert.equal((await call('PUT', '/api/admin/users/nope/plan', { token: a.json.token, body: { plan: 'FREE' } })).status, 404);
});
