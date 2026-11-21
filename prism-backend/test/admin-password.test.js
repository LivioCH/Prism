process.env.NODE_ENV = 'test';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';

let server, base, db;
const call = async (method, path, { token, body } = {}) => {
  const res = await fetch(base + path, {
    method,
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
};
const signup = (email, password = 'oldpass1') => call('POST', '/api/auth/signup', { body: { name: 'T', email, password } });
const login = (email, password) => call('POST', '/api/auth/login', { body: { email, password } });

before(() => {
  db = openDb(':memory:');
  server = createApp(db).listen(0);
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

test('an admin sets a new password for another account; the old one stops working', async () => {
  const victim = await signup('forgot@example.com');
  const boss = await signup('boss@example.com');
  db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(boss.json.user.id);

  const r = await call('PUT', `/api/admin/users/${victim.json.user.id}/password`, { token: boss.json.token, body: { newPassword: 'brandnew1' } });
  assert.equal(r.status, 204);
  assert.equal((await login('forgot@example.com', 'oldpass1')).status, 401);
  assert.equal((await login('forgot@example.com', 'brandnew1')).status, 200);
  assert.equal((await login('boss@example.com', 'oldpass1')).status, 200, 'the admin own password is untouched');
});

test('only admins can do it, short passwords and unknown accounts are refused', async () => {
  const a = await signup('a@example.com');
  const b = await signup('b@example.com');
  const boss = await signup('boss2@example.com');
  db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(boss.json.user.id);

  assert.equal((await call('PUT', `/api/admin/users/${b.json.user.id}/password`, { body: { newPassword: 'whatever1' } })).status, 401);
  assert.equal((await call('PUT', `/api/admin/users/${b.json.user.id}/password`, { token: a.json.token, body: { newPassword: 'whatever1' } })).status, 403);
  assert.equal((await login('b@example.com', 'oldpass1')).status, 200, 'a refused request changed nothing');

  assert.equal((await call('PUT', `/api/admin/users/${b.json.user.id}/password`, { token: boss.json.token, body: { newPassword: '123' } })).status, 400);
  assert.equal((await call('PUT', '/api/admin/users/no-such-id/password', { token: boss.json.token, body: { newPassword: 'whatever1' } })).status, 404);
});
