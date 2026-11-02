import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan } from '../src/scanner.js';

const run = (url, advanced = false) => scan('URL', url, { blocklist: new Set(), advanced });

// Links that must NOT be SAFE. `min` is the lowest acceptable verdict.
const BAD = [
  ['http://plurebo-verify.xyz', 'SUSPICIOUS'],
  ['https://plurebo-secure-login.top', 'SUSPICIOUS'],
  ['https://plurebo.com.account-verify.online', 'DANGEROUS'],
  ['https://plureb0-login.xyz', 'SUSPICIOUS'],
  ['http://185.220.101.45/login', 'SUSPICIOUS'],
  ['116-region.ru/wp-includes/capitalone360/fe3ffaf9fd4d58da65d987df9fcb7b', 'SUSPICIOUS'],
];
const ORDER = { SAFE: 0, SUSPICIOUS: 1, DANGEROUS: 2 };

for (const advanced of [false, true]) {
  for (const [url, min] of BAD) {
    test(`flags ${url} (advanced=${advanced})`, () => {
      const r = run(url, advanced);
      assert.ok(ORDER[r.verdict] >= ORDER[min], `${url} -> ${r.verdict} (${r.score}), expected >= ${min}`);
      assert.ok(r.reasons.length > 0);
    });
  }
}

for (const url of ['https://www.google.com', 'https://github.com', 'https://www.wikipedia.org', 'https://airline.com', 'https://pineapple.com']) {
  for (const advanced of [false, true]) {
    test(`keeps ${url} SAFE with a positive reason (advanced=${advanced})`, () => {
      const r = run(url, advanced);
      assert.equal(r.verdict, 'SAFE', `${url} -> ${r.verdict} (${r.score})`);
      assert.ok(r.reasons.length >= 1, 'SAFE must still carry a reason');
      assert.match(r.reasons[0].detail, /No obvious suspicious features/);
    });
  }
}

test('reasons have rule/detail/points/severity and are sorted by severity', () => {
  const r = run('https://plurebo.com.account-verify.online');
  const rank = { high: 3, medium: 2, low: 1 };
  for (const x of r.reasons) {
    assert.deepEqual(Object.keys(x).sort(), ['detail', 'points', 'rule', 'severity']);
    assert.match(x.detail, /[一-鿿]/); // Traditional Chinese text
  }
  for (let i = 1; i < r.reasons.length; i++) {
    assert.ok(rank[r.reasons[i - 1].severity] >= rank[r.reasons[i].severity]);
  }
});

test('brand match is whole-label only: airline/pineapple are fine, paypal-login is not', () => {
  assert.ok(!run('https://airline.com').reasons.some((x) => x.rule === 'brand_impersonation'));
  assert.ok(!run('https://pineapple.com').reasons.some((x) => x.rule === 'brand_impersonation'));
  assert.ok(run('https://paypal-login.top').reasons.some((x) => x.rule === 'brand_impersonation'));
  assert.ok(run('https://login.paypal.evil.com').reasons.some((x) => x.rule === 'brand_impersonation'));
});

test('a single sensitive word in the path never reaches DANGEROUS', () => {
  for (const path of ['account', 'update', 'bank', 'secure']) {
    const r = run(`https://example.com/${path}`);
    assert.equal(r.verdict, 'SAFE', `/${path} -> ${r.verdict}`);
  }
});

test('invalid input is reported as a reason, not thrown', () => {
  const r = run('not a url');
  assert.ok(r.reasons.some((x) => x.rule === 'invalid_url'));
});

// ---------- redirect chains / embedded URLs / "@" / whitespace ----------
const CHAIN = 'http:// t-info.mail.adobe.com/r/?id=xxx&p1=t.mid.accor-mail.com/r/?id=yyy&p1=filepmgklf.com/victim @domain.com';

test('redirect chain with hidden domain, "@" and a space is flagged, not rejected', () => {
  for (const advanced of [false, true]) {
    const r = run(CHAIN, advanced);
    assert.ok(ORDER[r.verdict] >= ORDER.SUSPICIOUS, `-> ${r.verdict} (${r.score})`);
    assert.ok(!r.reasons.some((x) => x.rule === 'invalid_url'), 'must not be rejected as invalid');
    assert.ok(r.reasons.some((x) => x.rule === 'whitespace' && /空白字元/.test(x.detail)));
    assert.ok(r.reasons.some((x) => x.rule === 'at_sign' && x.detail.includes('@')));
    assert.ok(r.reasons.some((x) => x.rule === 'embedded_url' && x.detail.includes('filepmgklf.com')));
  }
});

test('whitespace is trimmed at the ends silently, flagged only when inside', () => {
  assert.ok(!run('  https://github.com  ').reasons.some((x) => x.rule === 'whitespace'));
  assert.ok(run('https://git hub.com').reasons.some((x) => x.rule === 'whitespace'));
});

test('"@" in the host part: the real host is the part after it', () => {
  const r = run('http://www.google.com@evil-site.xyz/login');
  assert.ok(r.reasons.some((x) => x.rule === 'userinfo' && x.detail.includes('@')));
  assert.ok(r.reasons.some((x) => x.rule === 'risky_tld' && x.detail.includes('.xyz')), 'evil-site.xyz must be analysed');
});

test('a blocklisted domain hidden behind a clean front domain decides the verdict', () => {
  const ctx = { blocklist: new Set(['evil-hidden.com']), advanced: false };
  const r = scan('URL', 'https://www.google.com/redirect?url=http://evil-hidden.com/x', ctx);
  assert.equal(r.verdict, 'DANGEROUS');
  assert.ok(r.reasons.some((x) => x.rule === 'blocklisted' && x.detail.includes('evil-hidden.com')));
  // same front URL without the hidden domain on the blocklist stays below DANGEROUS
  assert.notEqual(run('https://www.google.com/redirect?url=http://evil-hidden.com/x').verdict, 'DANGEROUS');
});

test('normal links with query strings are not mistaken for chains', () => {
  for (const u of ['https://github.com/search?q=report.pdf&page=2', 'https://www.google.com/search?q=hello+world', 'https://www.wikipedia.org/wiki/Main_Page?x=1']) {
    assert.equal(run(u).verdict, 'SAFE', u);
  }
});

const GCLID = 'https://pontosapontamentolu.com/gclid/=/c/?gclid=ishecabh95cvbhb1eiwagy6m4vn7url3tlj5m_nu__lcyj4n06pqquydbh-56148buwwbmv7k1qejboci-isjw5_kiq';

test('gclid used as a path folder is at least SUSPICIOUS; URL length never lowers the score', () => {
  const r = run(GCLID);
  assert.ok(ORDER[r.verdict] >= ORDER.SUSPICIOUS, `${r.verdict} ${r.score}`);
  assert.ok(r.reasons.some((x) => x.rule === 'tracking_in_path'));
  assert.ok(r.reasons.some((x) => x.rule === 'random_query_token'));
  assert.ok(r.reasons.every((x) => x.points >= 0));
  assert.ok(r.reasons.some((x) => x.rule === 'long_url' && x.points > 0));
});

test('a real ?gclid= in the query is not flagged as a path parameter; controls stay SAFE', () => {
  assert.ok(!run('https://www.google.com/?gclid=abc').reasons.some((x) => x.rule === 'tracking_in_path'));
  for (const u of ['https://www.google.com', 'https://github.com']) assert.equal(run(u).verdict, 'SAFE');
});

// ---------- Taiwan phone + Traditional-Chinese wording ----------
const phone = (n) => scan('PHONE', n, { blocklist: new Set(), advanced: false });
const msg = (t) => scan('MESSAGE', t, { blocklist: new Set(), advanced: false });

test('Taiwan phone: valid mobile and landline formats are SAFE', () => {
  for (const n of ['0912345678', '0912-345-678', '0912 345 678', '(02) 2345-6789', '02-23456789', '037-123456', '049-2345678']) {
    assert.equal(phone(n).threat, 'SAFE', n);
  }
});

test('Taiwan phone: +886 is a valid international format and is NOT flagged', () => {
  assert.equal(phone('+886912345678').threat, 'SAFE');
  assert.equal(phone('+886 2 2345 6789').threat, 'SAFE');
  assert.ok(phone('+886912345678').reasons.every((x) => x.rule !== 'fake_local_intl'));
});

test('Phone: valid numbers from other countries are not flagged just for being foreign', () => {
  for (const n of ['+62 812 3456 7890', '+44 20 7946 0958', '+81 3 1234 5678']) {
    const r = phone(n);
    assert.equal(r.threat, 'SAFE', n);
    assert.ok(r.reasons.every((x) => x.rule !== 'foreign_number' && x.rule !== 'risky_country'), n);
  }
  assert.notEqual(phone('1234').threat, 'SAFE'); // still too short
});

test('Chinese wording: harmless message is SAFE', () => {
  assert.equal(msg('明天見面嗎').threat, 'SAFE');
});

test('Chinese wording: bad link + account threat + urgency is DANGER', () => {
  const r = msg('您的帳號異常，請立即點擊 http://plurebo-verify.xyz 驗證');
  assert.equal(r.threat, 'DANGER');
  assert.ok(r.reasons.some((x) => x.rule === 'zh_account_threat' && x.detail.includes('帳號異常')));
  assert.ok(r.reasons.some((x) => x.rule === 'zh_urgency' && x.detail.includes('立即')));
});

test('Chinese wording without a link: prize bait is SUSPICIOUS, one weak category alone is SAFE', () => {
  assert.equal(msg('恭喜中獎，請提供信用卡領取').threat, 'WARNING');
  assert.equal(msg('您的帳號異常，請立即處理').threat, 'WARNING');
  assert.equal(msg('我的包裹到了嗎').threat, 'SAFE');
});
