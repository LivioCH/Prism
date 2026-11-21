process.env.NODE_ENV = 'test';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';
import { createWebRiskDetector, extractLinks } from '../src/webrisk.js';

// Stand-in for Google Web Risk, so tests never call the real API.
const fake = { listed: {}, fail: false, calls: [] };
const fakeChecker = {
  checkUrl: async (url) => {
    fake.calls.push(url);
    if (fake.fail) throw new Error('down');
    return { url, threatTypes: fake.listed[url] ?? [] };
  },
};

let server, base, plainServer, plainBase;
before(() => {
  server = createApp(openDb(':memory:'), { linkChecker: fakeChecker }).listen(0);
  base = `http://127.0.0.1:${server.address().port}`;
  plainServer = createApp(openDb(':memory:')).listen(0);             // no key configured
  plainBase = `http://127.0.0.1:${plainServer.address().port}`;
});
after(() => { server.close(); plainServer.close(); });

const call = async (root, method, path, { token, body } = {}) => {
  const res = await fetch(root + path, {
    method,
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
};
let n = 0;
const newUser = async (root, plan = 'PLUS') => {
  const s = await call(root, 'POST', '/api/auth/signup', { body: { name: 'T', email: `wr${++n}@example.com`, password: 'secret1' } });
  await call(root, 'PUT', '/api/subscription', { token: s.json.token, body: { plan } });
  return s.json.token;
};

test('a listed link in a message makes the scan DANGER and lands in history', async () => {
  const token = await newUser(base);
  fake.fail = false; fake.calls = [];
  fake.listed = { 'http://evil-login.xyz/verify': ['SOCIAL_ENGINEERING'] };
  const r = await call(base, 'POST', '/api/scans/webrisk', {
    token, body: { text: 'Your account is locked, verify at evil-login.xyz/verify or https://www.google.com.' },
  });
  assert.equal(r.status, 201);
  assert.equal(r.json.isDangerous, true);
  assert.equal(r.json.scan.threat, 'danger');
  assert.equal(r.json.scan.type, 'message');
  assert.equal(r.json.scan.details, 'Google lists evil-login.xyz as a phishing site');
  assert.deepEqual(fake.calls, ['http://evil-login.xyz/verify', 'https://www.google.com']);
  assert.deepEqual(r.json.results[0].threats, ['phishing']);
  const hist = await call(base, 'GET', '/api/scans', { token });
  assert.equal(hist.json.scans[0].source, 'webrisk');
});

test('an unlisted single link is SAFE and stored as a URL scan', async () => {
  const token = await newUser(base);
  fake.fail = false; fake.listed = {};
  const r = await call(base, 'POST', '/api/scans/webrisk', { token, body: { text: 'https://example.com' } });
  assert.equal(r.json.scan.threat, 'safe');
  assert.equal(r.json.scan.type, 'url');
  assert.equal(r.json.scan.details, "This link is not on Google's list of dangerous sites");
});

test('a failing Web Risk call is a 502, never a verdict', async () => {
  const token = await newUser(base);
  fake.fail = true;
  const r = await call(base, 'POST', '/api/scans/webrisk', { token, body: { text: 'https://example.com' } });
  assert.equal(r.status, 502);
  assert.equal(r.json.error.code, 'webrisk_failed');
});

test('text without links is rejected, not called safe', async () => {
  const token = await newUser(base);
  fake.fail = false; fake.calls = [];
  const r = await call(base, 'POST', '/api/scans/webrisk', { token, body: { text: 'Lunch at 1? see report.pdf' } });
  assert.equal(r.status, 400);
  assert.equal(r.json.error.code, 'no_links');
  assert.deepEqual(fake.calls, []);
  assert.equal((await call(base, 'POST', '/api/scans/webrisk', { token, body: { text: '  ' } })).status, 400);
  assert.equal((await call(base, 'POST', '/api/scans/webrisk', { body: { text: 'https://a.com' } })).status, 401);
});

test('without WEB_RISK_API_KEY the route answers 503', async () => {
  const token = await newUser(plainBase);
  const r = await call(plainBase, 'POST', '/api/scans/webrisk', { token, body: { text: 'https://a.com' } });
  assert.equal(r.status, 503);
  assert.equal(r.json.error.code, 'webrisk_unavailable');
});

test('scanner: a brand domain inside an official login link is not a hidden redirect', async () => {
  const { scan } = await import('../src/scanner.js');
  const ctx = { blocklist: new Set(), advanced: false };
  const login = 'https://www.facebook.com/oidc/?app_id=1&redirect_uri=https%3A%2F%2Fwww.instagram.com%2Faccounts%2Fsignupviafb%2F&response_type=code';
  const r = scan('URL', login, ctx);
  assert.equal(r.threat, 'SAFE');
  assert.ok(!r.reasons.some((x) => x.rule === 'embedded_url'));
  const bounce = scan('URL', 'https://www.facebook.com/l.php?u=http%3A%2F%2Fevil-login.xyz%2Fverify', ctx);
  assert.ok(bounce.reasons.some((x) => x.rule === 'embedded_url' && x.detail.includes('evil-login.xyz')));
});

test('links are pulled out of a message', () => {
  assert.deepEqual(
    extractLinks('Go to https://a.com/x?y=1, then www.b.org. Also c-d.xyz/login! Mail me@e.com, open f.pdf'),
    ['https://a.com/x?y=1', 'http://www.b.org', 'http://c-d.xyz/login'],
  );
  assert.deepEqual(extractLinks('https://a.com and https://a.com'), ['https://a.com']);
});

test('Web Risk client sends the documented request and reads both response shapes', async () => {
  const seen = [];
  const reply = (status, body) => async (url) => { seen.push(new URL(url)); return new Response(JSON.stringify(body), { status }); };

  let d = createWebRiskDetector({ apiKey: 'k', baseUrl: 'https://x.test', fetchImpl: reply(200, { threat: { threatTypes: ['MALWARE'], expireTime: '2030-01-01T00:00:00Z' } }) });
  assert.deepEqual(await d.checkUrl('http://bad.test/'), { url: 'http://bad.test/', threatTypes: ['MALWARE'] });
  const u = seen[0];
  assert.equal(u.pathname, '/v1/uris:search');
  assert.equal(u.searchParams.get('uri'), 'http://bad.test/');
  assert.equal(u.searchParams.get('key'), 'k');
  assert.deepEqual(u.searchParams.getAll('threatTypes'), ['SOCIAL_ENGINEERING', 'MALWARE', 'UNWANTED_SOFTWARE']);

  d = createWebRiskDetector({ apiKey: 'k', baseUrl: 'https://x.test', fetchImpl: reply(200, {}) });
  assert.deepEqual((await d.checkUrl('https://ok.test')).threatTypes, []);

  d = createWebRiskDetector({ apiKey: 'k', baseUrl: 'https://x.test', fetchImpl: reply(403, { error: {} }) });
  await assert.rejects(d.checkUrl('https://ok.test'));
  d = createWebRiskDetector({ apiKey: 'k', baseUrl: 'https://x.test', fetchImpl: reply(200, { threat: {} }) });
  await assert.rejects(d.checkUrl('https://ok.test'));
});
