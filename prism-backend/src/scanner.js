// Rule-based threat scoring for URLs, phone numbers and messages.
// Each check yields signals {id, weight, text}. Total weight -> SAFE / WARNING / DANGER.
// This is heuristic detection plus a community blocklist; it is NOT a threat-intel feed.
// To add one (e.g. Google Safe Browsing), call it in scanUrl() and push a signal.

const DANGER_AT = 60;
const WARNING_AT = 25;

const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc']);
const RISKY_TLDS = new Set(['zip', 'mov', 'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'work', 'support', 'country', 'kim', 'loan', 'men', 'icu', 'cyou', 'rest', 'online']);
const TRACKING_PARAMS = new Set(['gclid', 'fbclid', 'msclkid', 'dclid', 'gbraid', 'wbraid', 'yclid', 'ttclid', 'twclid', 'igshid', 'mc_eid', 'mc_cid', 'gclsrc']);
const URL_KEYWORDS = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'wallet', 'bank', 'confirm', 'password', 'suspend', 'unlock', 'billing', 'invoice', 'refund'];
const SECOND_LEVEL = new Set(['co.uk', 'org.uk', 'com.au', 'co.jp', 'co.id', 'com.tw', 'com.br', 'co.in', 'com.sg', 'com.cn', 'com.hk', 'co.nz']);

// brand label -> legitimate registrable domains
const BRANDS = {
  paypal: ['paypal.com'], apple: ['apple.com', 'icloud.com'], google: ['google.com', 'gmail.com'],
  microsoft: ['microsoft.com', 'live.com', 'office.com'], amazon: ['amazon.com'], netflix: ['netflix.com'],
  facebook: ['facebook.com'], instagram: ['instagram.com'], whatsapp: ['whatsapp.com'], dhl: ['dhl.com'],
  fedex: ['fedex.com'], usps: ['usps.com'], chase: ['chase.com'], wellsfargo: ['wellsfargo.com'],
  bankofamerica: ['bankofamerica.com'], shopee: ['shopee.com'], line: ['line.me'], telkomsel: ['telkomsel.com'],
};

const verdict = (score, t = { warning: WARNING_AT, danger: DANGER_AT }) =>
  (score >= t.danger ? 'DANGER' : score >= t.warning ? 'WARNING' : 'SAFE');
// Public names used by the Manual Scan UI
const VERDICT_NAMES = { SAFE: 'SAFE', WARNING: 'SUSPICIOUS', DANGER: 'DANGEROUS' };
const SEVERITY_RANK = { high: 3, medium: 2, low: 1 };

// ---------- helpers ----------
export function normalizeUrl(raw) {
  const trimmed = raw.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  try {
    const u = new URL(withScheme);
    if (!['http:', 'https:'].includes(u.protocol)) return null;
    if (!u.hostname.includes('.') && !/^\[.*\]$/.test(u.hostname)) return null;
    return { url: u, hadScheme: withScheme === trimmed };
  } catch {
    return null;
  }
}

export function registrableDomain(host) {
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join('.');
  return SECOND_LEVEL.has(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
}

export function normalizePhone(raw) {
  const digits = raw.replace(/\D/g, '');
  return { digits, plus: raw.trim().startsWith('+') };
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return dp[a.length][b.length];
}

// ---------- URL ----------
// URL verdicts use their own thresholds: SAFE < 30, SUSPICIOUS 30-69, DANGEROUS >= 70.
const URL_THRESHOLDS = { warning: 30, danger: 70 };
const TLD_LOOKALIKES = new Set(['com', 'net', 'org', 'gov', 'edu']);

// severity of a single reason, derived from its points
const severityOf = (points) => (points >= 35 ? 'high' : points >= 15 ? 'medium' : 'low');

// Every scoring rule goes through here so it always yields a user-readable reason:
// { rule, detail (Traditional Chinese), points, severity }. id/weight/text stay for API compatibility.
const reason = (id, weight, text, detail) => ({
  id, weight, text,
  rule: id, detail, points: weight, severity: severityOf(weight),
});

// Extensions that look like a domain ("report.pdf") but are just file names inside a query string.
const FILE_EXT = new Set(['pdf', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'html', 'htm', 'php', 'asp', 'aspx', 'jsp', 'js', 'css', 'json', 'xml', 'txt', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'mp3', 'mp4', 'csv']);
const DOMAIN_IN_TEXT = /(?:https?:\/\/)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24})(?![a-z0-9-])/gi;

const safeDecode = (s) => { try { return decodeURIComponent(s); } catch { return s; } };

// Other domains hidden in the query string / fragment, e.g. "?p1=filepmgklf.com/victim".
// strong = the domain starts a parameter value or has a scheme (a real redirect target).
function findHiddenDomains(url, frontDomain) {
  const text = safeDecode(url.search + url.hash);
  const found = [];
  for (const m of text.matchAll(DOMAIN_IN_TEXT)) {
    const host = m[1].toLowerCase();
    if (FILE_EXT.has(host.split('.').pop())) continue;
    const prev = text[m.index - 1] ?? '';
    if (prev === '@') continue; // handled by the "@" rule
    const domain = registrableDomain(host);
    if (domain === frontDomain || found.some((f) => f.domain === domain)) continue;
    found.push({ host, domain, strong: prev === '=' || /^https?:\/\//i.test(m[0]) });
  }
  return found;
}

// Scores ONE host. Used for the visible host and for every host hidden inside the URL.
// checkHttps is false for hidden hosts because their real scheme is unknown.
function scoreHost(url, { blocklist, advanced }, { checkHttps = true } = {}) {
  const signals = [];
  const host = url.hostname.toLowerCase();
  const domain = registrableDomain(host);
  const tld = domain.split('.').pop();
  const hostLabels = host.split('.');
  // A known brand's own domain (e.g. accounts.google.com) is trusted: skip wording/brand checks.
  const trusted = Object.values(BRANDS).some((d) => d.includes(domain));

  if (blocklist.has(host) || blocklist.has(domain)) {
    signals.push(reason('blocklisted', 100, 'Reported as malicious by other users', '此網址已被多位使用者回報為惡意網站'));
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^\[.*\]$/.test(host)) {
    signals.push(reason('ip_host', 40, 'Uses a raw IP address instead of a domain name', '使用 IP 位址而不是正常的網域名稱，正規網站很少這樣做'));
  }
  if (url.username || url.password) {
    // url.hostname is already the part AFTER the "@", i.e. the real destination
    signals.push(reason('userinfo', 35, 'Contains a hidden login section (@) that disguises the real site', '網址使用 @ 符號隱藏真實網域'));
  }
  if (hostLabels.some((l) => l.startsWith('xn--'))) {
    signals.push(reason('punycode', 30, 'Uses look-alike international characters', '網域使用外觀相似的特殊字元，可能偽裝成其他網站'));
  }
  if (checkHttps && url.protocol === 'http:') {
    signals.push(reason('no_https', 10, 'Connection is not encrypted (HTTP)', '連線未加密（HTTP），輸入的資料可能被竊取'));
  }
  if (RISKY_TLDS.has(tld)) {
    signals.push(reason('risky_tld', 20, `.${tld} domains are frequently abused`, `網域使用高風險結尾 .${tld}`));
  }
  // "plurebo.com.evil.online": a .com/.net label placed before the real domain to look official.
  const before = hostLabels.slice(0, hostLabels.length - domain.split('.').length);
  const fakeTld = before.find((l) => TLD_LOOKALIKES.has(l));
  if (fakeTld) {
    signals.push(reason('fake_tld_label', 25, 'Fake ".com" inside the subdomain', `網址前段偽裝成 .${fakeTld} 結尾，實際網域是 ${domain}`));
  }
  if (hostLabels.length >= 5) {
    signals.push(reason('deep_subdomain', 15, 'Unusually many subdomains', '子網域層數異常偏多'));
  }
  if (SHORTENERS.has(domain)) {
    signals.push(reason('shortener', 15, 'Link shortener hides the real destination', '使用短網址，看不出真正的目的地'));
  }

  // Sensitive wording: strong signal in the domain/subdomain, only a weak one in the path,
  // so a single word like /account in a path can never reach DANGEROUS by itself.
  const pathText = url.pathname.toLowerCase();
  const hostKw = trusted ? [] : URL_KEYWORDS.filter((k) => host.includes(k));
  const pathKw = trusted ? [] : URL_KEYWORDS.filter((k) => !hostKw.includes(k) && pathText.includes(k));
  if (hostKw.length) {
    signals.push(reason('keywords_host', Math.min(35, hostKw.length * 15), `Sensitive wording in domain (${hostKw.slice(0, 3).join(', ')})`,
      `網域名稱含有敏感字眼（${hostKw.slice(0, 3).join('、')}），常見於假冒登入或驗證頁面`));
  }
  if (pathKw.length) {
    signals.push(reason('keywords_path', Math.min(6, pathKw.length * 3), `Sensitive wording in path (${pathKw.slice(0, 3).join(', ')})`,
      `網址路徑含有敏感字眼（${pathKw.slice(0, 3).join('、')}）`));
  }
  if ((host.match(/-/g) || []).length >= 3) {
    signals.push(reason('hyphens', 10, 'Many hyphens in domain name', '網域中的連字號過多'));
  }
  // URL length is NEUTRAL-to-bad: it can only add points, never lower the score or count as a "safe" reason.
  if (url.href.length > 100) {
    signals.push(reason('long_url', 5, 'Very long address', '網址異常冗長'));
  }
  // Tracking parameters (gclid, utm_*, fbclid...) are real only as "?gclid=..." in the query string.
  // Seen as a folder/segment of the PATH ("/gclid/=/c/") they are a common fake-ad / cloaking trick.
  const trackingInPath = url.pathname.split('/').map((s) => {
    let d = s; try { d = decodeURIComponent(s); } catch { /* keep raw */ }
    return d.toLowerCase().split('=')[0];
  }).filter((n) => TRACKING_PARAMS.has(n) || n.startsWith('utm_'));
  if (trackingInPath.length) {
    signals.push(reason('tracking_in_path', 30, 'Tracking parameter appears in the URL path (possibly forged)',
      '追蹤參數出現在網址路徑中，可能為偽造'));
  }
  // Phishing kits are often dropped into hacked WordPress sites: /wp-includes/ and /wp-admin/ are
  // never real landing pages (static files like .js/.css/.png are ignored).
  if (/\/wp-(includes|admin)\//i.test(url.pathname) && !/\.(js|css|png|jpe?g|gif|svg|ico|woff2?|map)$/i.test(url.pathname)) {
    signals.push(reason('cms_path', 20, 'Page hosted inside a CMS system folder (/wp-includes, /wp-admin)',
      '網頁放在網站系統資料夾（wp-includes / wp-admin）內，常見於被入侵網站上的釣魚頁面'));
  }
  // A long hex string (24+ chars, letters and digits) as a path segment: auto-generated victim/kit id.
  if (url.pathname.split('/').some((s) => /^[a-f0-9]{24,}$/i.test(s) && /\d/.test(s) && /[a-f]/i.test(s))) {
    signals.push(reason('hex_path', 15, 'Long random identifier in the path', '網址路徑含有很長的隨機識別碼'));
  }
  // One very long random-looking token (>50 chars, has digits and letters) in the query.
  if (/[A-Za-z0-9_-]{51,}/.test(url.search) && [...url.search.matchAll(/[A-Za-z0-9_-]{51,}/g)].some((m) => /\d/.test(m[0]) && /[a-z]/i.test(m[0]))) {
    signals.push(reason('random_query_token', 10, 'Unusually long random-looking parameter', '網址含有異常長的隨機參數'));
  }
  // HONEST LIMIT: a domain that is genuinely clean-looking (HTTPS, common TLD, no keywords, not a brand
  // look-alike) can still be a phishing site and will score SAFE. That is a limit of local heuristics,
  // not a bug; catching it needs a Gemini layer or threat intelligence.

  // Brand impersonation: the brand must be a whole label, or a whole "-"-separated part of a label
  // ("paypal-login" matches, "airline"/"pineapple" do not match "line"/"apple").
  if (!trusted) {
    for (const [brand, legit] of Object.entries(BRANDS)) {
      const labelHasBrand = (l) => l === brand || l.split('-').includes(brand);
      const mentionsBrand = hostLabels.some(labelHasBrand) || (pathText.includes(brand) && (hostKw.length || pathKw.length));
      if (mentionsBrand && !legit.includes(domain)) {
        signals.push(reason('brand_impersonation', 40, `Appears to impersonate ${brand}`, `網域疑似假冒 ${brand} 品牌，但並不是官方網站`));
        break;
      }
      if (advanced) {
        const label = domain.split('.')[0].replace(/[0-9]/g, (d) => ({ 0: 'o', 1: 'l', 3: 'e', 5: 's' }[d] ?? d));
        if (label !== brand && levenshtein(label, brand) <= 1 && brand.length >= 5) {
          signals.push(reason('typosquat', 45, `Domain closely mimics ${brand}`, `網域與 ${brand} 非常相似，可能是拼字仿冒`));
          break;
        }
      }
    }
  }
  return signals;
}

const sumPoints = (signals) => signals.reduce((s, x) => s + x.weight, 0);

export function scanUrl(raw, ctx) {
  // Pre-clean: trim the ends; whitespace INSIDE the link is removed but flagged, not rejected.
  const trimmed = raw.trim();
  const hasInnerSpace = /\s/.test(trimmed);
  const parsed = normalizeUrl(trimmed.replace(/\s+/g, ''));
  if (!parsed) {
    return finish([reason('invalid_url', 30, 'Not a valid web address', '這不是有效的網址格式')], URL_THRESHOLDS);
  }
  const { url } = parsed;
  const frontDomain = registrableDomain(url.hostname.toLowerCase());

  // Rules about the URL as a whole: they apply to the visible host AND to every hidden one.
  const context = [];
  if (hasInnerSpace) {
    context.push(reason('whitespace', 15, 'Contains whitespace', '網址含有空白字元，可能被刻意變造'));
  }
  // An "@" outside the host part (path/query). In "http://a.com/x?y=u@b.com" the text after the "@"
  // looks like the destination. (An "@" in the host part is already handled by scoreHost's userinfo rule.)
  const atMatch = !url.username && !url.password
    ? /@((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24})/i.exec(safeDecode(url.pathname + url.search + url.hash))
    : null;
  if (atMatch) {
    context.push(reason('at_sign', 35, 'Contains an "@" that hides the real domain', '網址使用 @ 符號隱藏真實網域'));
  }
  const hidden = findHiddenDomains(url, frontDomain);
  if (hidden.length) {
    const strong = hidden.some((h) => h.strong);
    context.push(reason('embedded_url', strong ? 30 : 15, 'Another domain is hidden inside the address',
      `網址內隱藏其他網域（可能的轉址詐騙）：${hidden.map((h) => h.domain).join('、')}`));
  }

  // Candidate hosts: the visible one plus everything hidden. The WORST one decides the verdict,
  // so a clean-looking front domain can't cover for a malicious hidden one.
  const hiddenHosts = hidden.map((h) => h.host);
  if (atMatch) hiddenHosts.push(atMatch[1].toLowerCase());
  const candidates = [{ label: null, signals: scoreHost(url, ctx) }];
  for (const h of [...new Set(hiddenHosts)]) {
    let u;
    try { u = new URL(`https://${h}`); } catch { continue; }
    const own = scoreHost(u, ctx, { checkHttps: false }).map((s) => ({
      ...s, text: `[${h}] ${s.text}`, detail: `（${h}）${s.detail}`,
    }));
    candidates.push({ label: h, signals: own });
  }
  const worst = candidates.reduce((a, b) => (sumPoints(b.signals) > sumPoints(a.signals) ? b : a));
  const signals = [...context, ...worst.signals];

  // Nothing found -> give the SAFE card a neutral positive reason instead of an empty list.
  if (!signals.length) {
    signals.push(reason('no_issues', 0, 'No obvious suspicious features', '未發現明顯可疑特徵（使用 HTTPS、網域結構正常）'));
  }
  return finish(signals, URL_THRESHOLDS);
}

// ---------- PHONE ----------
const NANP_CARIBBEAN = new Set(['242', '246', '264', '268', '284', '340', '345', '441', '473', '649', '664', '721', '758', '767', '784', '809', '829', '849', '868', '869', '876']);

export function scanPhone(raw, { blocklist }) {
  const { digits, plus } = normalizePhone(raw);
  const signals = [];
  if (digits.length < 7 || digits.length > 15) {
    signals.push({ id: 'bad_format', weight: 30, text: 'Not a valid phone number length' });
    return finish(signals);
  }
  if (blocklist.has(digits)) {
    signals.push({ id: 'blocklisted', weight: 100, text: 'Reported as a scam number by other users' });
  }
  const national = plus || digits.length === 11 ? digits.replace(/^1/, '') : digits;
  const nanp = (plus && digits.startsWith('1') && digits.length === 11) || digits.length === 10;
  if (nanp) {
    const area = national.slice(0, 3);
    if (['900', '976'].includes(area)) signals.push({ id: 'premium', weight: 45, text: 'Premium-rate number - calling can be very costly' });
    if (NANP_CARIBBEAN.has(area)) signals.push({ id: 'one_ring', weight: 30, text: 'Area code commonly used in "one-ring" callback scams' });
  }
  if (/(\d)\1{6,}/.test(digits)) {
    signals.push({ id: 'repeated', weight: 25, text: 'Suspicious repeated digits' });
  }
  if (!plus && digits.length > 11) {
    signals.push({ id: 'intl_no_plus', weight: 10, text: 'International-length number without + prefix' });
  }
  return finish(signals);
}

// ---------- MESSAGE ----------
const MESSAGE_RULES = [
  { id: 'urgency', weight: 15, re: /\b(urgent|immediately|act now|within 24 hours|final notice|last warning|expires? (today|soon))\b/i, text: 'Creates false urgency' },
  { id: 'credentials', weight: 30, re: /\b(password|passcode|pin|cvv|otp|one[- ]time (code|password)|verification code|ssn|social security)\b/i, text: 'Asks for credentials or codes' },
  { id: 'account_threat', weight: 20, re: /\b(account|card).{0,30}\b(suspended|locked|closed|compromised|restricted|disabled)\b/i, text: 'Threatens account suspension' },
  { id: 'payment_method', weight: 30, re: /\b(gift ?cards?|wire transfer|western union|bitcoin|crypto(currency)?|usdt|zelle|cash ?app)\b/i, text: 'Requests untraceable payment' },
  { id: 'prize', weight: 25, re: /\b(you('ve| have)? won|winner|lottery|prize|claim your|free (iphone|gift))\b/i, text: 'Prize or lottery bait' },
  { id: 'authority', weight: 15, re: /\b(irs|police|customs|tax office|court|arrest|warrant)\b/i, text: 'Impersonates an authority' },
  { id: 'job_scam', weight: 20, re: /\b(work from home|easy money|earn \$?\d+.{0,12}(per|a) (day|hour)|advance fee)\b/i, text: 'Too-good-to-be-true income offer' },
  { id: 'delivery', weight: 15, re: /\b(package|parcel|delivery).{0,40}\b(failed|held|pending|fee|reschedule)\b/i, text: 'Fake delivery notice pattern' },
];
const URL_IN_TEXT = /\b((?:https?:\/\/|www\.)[^\s<>"']+|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|info|xyz|top|click|work|support|zip|tk|ml|ga|cf|gq|me|io|co)\b[^\s<>"']*)/gi;

export function scanMessage(raw, ctx) {
  const signals = [];
  for (const r of MESSAGE_RULES) if (r.re.test(raw)) signals.push({ id: r.id, weight: r.weight, text: r.text });

  const links = [...new Set(raw.match(URL_IN_TEXT) || [])].slice(0, 5);
  if (links.length) {
    const worst = links.map((l) => scanUrl(l, ctx)).sort((a, b) => b.score - a.score)[0];
    if (worst.threat !== 'SAFE') {
      signals.push({ id: 'bad_link', weight: Math.min(60, worst.score), text: 'Contains a suspicious link' });
    } else {
      signals.push({ id: 'has_link', weight: 5, text: 'Contains a link' });
    }
  }
  return finish(signals);
}

// ---------- shared ----------
function finish(signals, thresholds) {
  const score = Math.min(100, signals.reduce((s, x) => s + x.weight, 0));
  const threat = verdict(score, thresholds);
  // reasons: same data as signals, highest severity first, always with rule/detail/points/severity
  const reasons = signals
    .map((x) => ({
      rule: x.rule ?? x.id, detail: x.detail ?? x.text, points: x.points ?? x.weight,
      severity: x.severity ?? severityOf(x.weight),
    }))
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.points - a.points);
  return { score, threat, verdict: VERDICT_NAMES[threat], signals, reasons };
}

export function describe(threat, signals) {
  const top = [...signals].sort((a, b) => b.weight - a.weight).slice(0, 2).map((s) => s.text);
  const tail = top.length ? ` - ${top.join('; ')}` : '';
  if (threat === 'DANGER') return `Potential scam detected${tail}`;
  if (threat === 'WARNING') return `Suspicious pattern found${tail || ' - Proceed with caution'}`;
  return 'No threats detected - Appears safe';
}

export function scan(type, content, ctx) {
  const result =
    type === 'URL' ? scanUrl(content, ctx) :
    type === 'PHONE' ? scanPhone(content, ctx) :
    scanMessage(content, ctx);
  return { ...result, details: describe(result.threat, result.signals) };
}
