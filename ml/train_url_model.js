// Trains the URL phishing model used by the Prism app (Prism-main/app/src/main/assets/url_model.json).
//
//   node ml/train_url_model.js [--data PhiUSIIL_Phishing_URL_Dataset.csv] [--out url_model.json]
//                              [--baseline ml/baseline_url_model_v1.json] [--no-write]
//
// Data:    PhiUSIIL Phishing URL Dataset (UCI). label 0 = phishing, 1 = legitimate. Only the URL and label columns are used.
// Model:   logistic regression on 15 features taken from the HOST NAME only (never the path or query).
//          Why host only: in PhiUSIIL almost every legitimate URL is a bare homepage, so a model that sees the path
//          learns "path = phishing" and flags real login pages such as https://school.edu/login/index.php.
// Split:   80% train / 20% test, split by host so the same site never appears in both sets.
// Port:    Kotlin twin = Prism-main/app/src/main/java/com/example/prism/scan/FeatureExtractor.kt. The order and the
//          formulas must stay identical; ml/parity_vectors.json (written here) is checked by a unit test.
const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
const arg = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
const ROOT = path.join(__dirname, '..');
const DATA = arg('--data', path.join(ROOT, 'PhiUSIIL_Phishing_URL_Dataset.csv'));
const OUT = arg('--out', path.join(ROOT, 'Prism-main/app/src/main/assets/url_model.json'));
const BASELINE = arg('--baseline', path.join(__dirname, 'baseline_url_model_v1.json'));
const WRITE = !args.includes('--no-write');

// ---------- constants shared with the app (written into the model file) ----------
const SUS_TLD = ['cf','click','country','download','ga','gq','icu','info','loan','ml','online','racing','stream','tk','top','win','work','xyz'];
const FREE_HOSTS = ['workers.dev','pages.dev','firebaseapp.com','web.app','weebly.com','wixsite.com','blogspot.com','herokuapp.com','netlify.app','vercel.app','github.io','glitch.me','000webhostapp.com','godaddysites.com','square.site','webflow.io','framer.app','myshopify.com','repl.co','replit.app','onrender.com','surge.sh','azurewebsites.net','cloudfront.net','ipfs.io','typedream.app','carrd.co','sites.google.com','weeblysite.com','jimdofree.com','yolasite.com','mystrikingly.com','duckdns.org','ngrok.io','trycloudflare.com','r2.dev','s3.amazonaws.com','storage.googleapis.com','rf.gd','epizy.com','infinityfreeapp.com','xsph.ru'];
const BRANDS = ['amazon','paypal','apple','google','microsoft','facebook','yahoo','netflix','ebay','instagram','whatsapp','dhl','fedex','chase','wellsfargo','linkedin','outlook','office365','icloud','steam','coinbase','binance','metamask','dropbox','adobe','docusign','usps','irs'];
const SECOND_LEVEL = ['co','com','org','net','gov','edu','ac','or','ne','go'];
const SECOND = new Set(SECOND_LEVEL);
// Endings used by schools, governments and the military (school.edu, uni.ac.jp, agency.gov.uk, base.mil): rarely phishing
const INSTITUTION_LIST = ['edu', 'gov', 'mil', 'ac', 'sch'];
const INSTITUTION = new Set(INSTITUTION_LIST);
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

const NAMES = ['host_length','has_ip','num_subdomains','sus_tld','host_hyphens','host_digits','host_entropy','longest_label',
  'free_host','brand_in_host','longest_digit_run','sld_length','tld_phish_rate','host_dots','institution'];

function parts(url) {
  const noScheme = url.replace(/^https?:\/\//i, '');
  // A leading "www." is dropped: in PhiUSIIL nearly every legitimate URL starts with it, so otherwise the model
  // learns "no www = phishing" and flags github.com or stackoverflow.com.
  const hostFull = noScheme.split('/')[0].split('?')[0].replace(/^www\./i, '');
  const host = hostFull.split(':')[0].toLowerCase();
  const labels = host.split('.');
  const tld = labels[labels.length - 1];
  const regN = labels.length >= 3 && SECOND.has(labels[labels.length - 2]) && tld.length === 2 ? 3 : 2;
  const sld = labels.length >= regN ? labels[labels.length - regN] : labels[0];
  return { hostFull, host, labels, tld, sld };
}
const entropy = (s) => { if (!s.length) return 0; const c = {}; for (const ch of s) c[ch] = (c[ch] || 0) + 1; let h = 0; for (const k in c) { const p = c[k] / s.length; h -= p * Math.log2(p); } return h; };

function features(url, tldRate, prior) {
  const P = parts(url);
  const host = P.host;
  const runs = host.match(/\d+/g) || [];
  return [
    P.hostFull.length,
    IPV4.test(P.hostFull) ? 1 : 0,
    Math.max(0, P.labels.length - 2),
    SUS_TLD.includes(P.tld) ? 1 : 0,
    [...host].filter((c) => c === '-').length,
    [...host].filter((c) => c >= '0' && c <= '9').length,
    entropy(host),
    Math.max(...P.labels.map((l) => l.length)),
    FREE_HOSTS.some((f) => host === f || host.endsWith('.' + f)) ? 1 : 0,
    BRANDS.some((b) => host.includes(b) && P.sld !== b) ? 1 : 0,
    runs.reduce((a, r) => Math.max(a, r.length), 0),
    P.sld.length,
    tldRate.has(P.tld) ? tldRate.get(P.tld) : prior,
    P.labels.length - 1,
    INSTITUTION.has(P.tld) || (P.labels.length >= 2 && INSTITUTION.has(P.labels[P.labels.length - 2])) ? 1 : 0,
  ];
}

// ---------- read the CSV (quoted fields may hold commas and newlines) ----------
function readDataset(file) {
  const txt = fs.readFileSync(file, 'utf8').replace(/^﻿/, '');
  const rows = []; let row = [], f = '', q = false;
  for (let i = 0; i < txt.length; i++) {
    const c = txt[i];
    if (q) { if (c === '"') { if (txt[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(f); f = ''; }
    else if (c === '\n') { row.push(f.replace(/\r$/, '')); rows.push(row); row = []; f = ''; }
    else f += c;
  }
  if (f || row.length) { row.push(f); rows.push(row); }
  const head = rows[0], iu = head.indexOf('URL'), il = head.indexOf('label');
  if (iu < 0 || il < 0) throw new Error('the CSV needs URL and label columns');
  return rows.slice(1).filter((r) => r.length === head.length).map((r) => ({ u: r[iu], y: r[il] === '0' ? 1 : 0 })); // y = 1 means phishing
}

const sig = (z) => 1 / (1 + Math.exp(-z));
const hash = (s) => { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; };
function auc(p, y) { const idx = [...p.keys()].sort((a, b) => p[a] - p[b]); let r = 0, np = 0; idx.forEach((k, i) => { if (y[k]) { r += i + 1; np++; } }); return (r - np * (np + 1) / 2) / (np * (y.length - np)); }

function main() {
  const data = readDataset(DATA);
  const train = [], test = [];
  for (const d of data) (hash(parts(d.u).host.replace(/^www\./, '')) % 10 < 8 ? train : test).push(d);
  console.log(`dataset ${data.length} rows (phishing ${data.filter((d) => d.y).length}) -> train ${train.length}, test ${test.length}`);

  // TLD "how often is this ending phishing", learned on the training set only, smoothed towards the overall rate
  const cnt = new Map(); let ph = 0;
  for (const d of train) { const t = parts(d.u).tld; const c = cnt.get(t) || [0, 0]; c[0]++; c[1] += d.y; cnt.set(t, c); ph += d.y; }
  const prior = ph / train.length, alpha = 20;
  const tldRate = new Map();
  for (const [t, [n, p]] of cnt) if (n >= 30) tldRate.set(t, (p + alpha * prior) / (n + alpha));

  const Xtr = train.map((d) => features(d.u, tldRate, prior)), Xte = test.map((d) => features(d.u, tldRate, prior));
  const ytr = train.map((d) => d.y), yte = test.map((d) => d.y);
  const F = NAMES.length;
  const mean = new Float64Array(F), scale = new Float64Array(F);
  for (const r of Xtr) for (let i = 0; i < F; i++) mean[i] += r[i];
  for (let i = 0; i < F; i++) mean[i] /= Xtr.length;
  for (const r of Xtr) for (let i = 0; i < F; i++) scale[i] += (r[i] - mean[i]) ** 2;
  for (let i = 0; i < F; i++) scale[i] = Math.sqrt(scale[i] / Xtr.length) || 1;
  const Z = (a) => a.map((r) => Float64Array.from(r, (v, i) => (v - mean[i]) / scale[i]));
  const Ztr = Z(Xtr), Zte = Z(Xte);

  // logistic regression, Adam, L2, classes weighted to balance
  const w = new Float64Array(F + 1), m1 = new Float64Array(F + 1), m2 = new Float64Array(F + 1);
  const lr = 0.05, l2 = 1e-4, b1 = 0.9, b2 = 0.999;
  const npos = ytr.reduce((a, b) => a + b, 0);
  const wpos = ytr.length / (2 * npos), wneg = ytr.length / (2 * (ytr.length - npos));
  for (let it = 1; it <= 600; it++) {
    const g = new Float64Array(F + 1);
    for (let n = 0; n < Ztr.length; n++) {
      const x = Ztr[n]; let z = w[F];
      for (let i = 0; i < F; i++) z += w[i] * x[i];
      const e = (sig(z) - ytr[n]) * (ytr[n] ? wpos : wneg);
      for (let i = 0; i < F; i++) g[i] += e * x[i];
      g[F] += e;
    }
    for (let i = 0; i <= F; i++) {
      const gi = g[i] / Ztr.length + (i < F ? l2 * w[i] : 0);
      m1[i] = b1 * m1[i] + (1 - b1) * gi; m2[i] = b2 * m2[i] + (1 - b2) * gi * gi;
      w[i] -= lr * (m1[i] / (1 - b1 ** it)) / (Math.sqrt(m2[i] / (1 - b2 ** it)) + 1e-8);
    }
  }
  const predict = (url) => { const x = features(url, tldRate, prior); let z = w[F]; for (let i = 0; i < F; i++) z += w[i] * (x[i] - mean[i]) / scale[i]; return sig(z); };
  const pNew = test.map((d) => predict(d.u));

  function report(name, p, thr) {
    let tp = 0, fp = 0, tn = 0, fn = 0;
    p.forEach((v, i) => { const f = v >= thr; if (yte[i]) { f ? tp++ : fn++; } else { f ? fp++ : tn++; } });
    const pr = tp / (tp + fp), rc = tp / (tp + fn);
    console.log(`${name.padEnd(8)} threshold ${thr}  accuracy ${((tp + tn) / yte.length).toFixed(3)}  precision ${pr.toFixed(3)}  recall ${rc.toFixed(3)}  F1 ${(2 * pr * rc / (pr + rc)).toFixed(3)}  legit flagged ${(fp / (fp + tn)).toFixed(3)}`);
  }
  console.log('\n--- test set (never seen in training) ---');
  if (fs.existsSync(BASELINE)) {
    const old = JSON.parse(fs.readFileSync(BASELINE, 'utf8'));
    const oldFeat = (url) => { // the old 14 whole-URL features
      // the old model saw the raw host (with "www."), so do not use parts() here, which drops it
      const noS = url.replace(/^https?:\/\//i, ''); const lower = url.toLowerCase();
      const rawHost = noS.split('/')[0].split('?')[0]; const rawLabels = rawHost.split('.');
      const P = { hostFull: rawHost, labels: rawLabels, tld: rawHost.split(':')[0].split('.').pop().toLowerCase() };
      let nd = 0, dots = 0, hy = 0, sp = 0, sl = 0;
      for (const c of url) { if (c >= '0' && c <= '9') nd++; else if (c === '.') dots++; else if (c === '-') hy++; else if ('@%=&?_~'.includes(c)) sp++; else if (c === '/') sl++; }
      return [url.length, P.hostFull.length, dots, hy, nd, sp, sl, IPV4.test(P.hostFull) ? 1 : 0, url.includes('@') ? 1 : 0, Math.max(0, P.labels.length - 2),
        old.sus_tld.includes(P.tld) ? 1 : 0, old.keywords.some((k) => lower.includes(k)) ? 1 : 0, Math.round(nd / url.length * 1e4) / 1e4, noS.includes('//') ? 1 : 0];
    };
    const pOld = test.map((d) => { const x = oldFeat(d.u); let z = old.intercept; for (let i = 0; i < 14; i++) z += old.coef[i] * (x[i] - old.mean[i]) / old.scale[i]; return sig(z); });
    console.log(`AUC  old ${auc(pOld, yte).toFixed(3)}   new ${auc(pNew, yte).toFixed(3)}`);
    for (const t of [0.5, 0.7]) { report('old', pOld, t); report('new', pNew, t); }
  } else {
    console.log(`AUC ${auc(pNew, yte).toFixed(3)}`);
    for (const t of [0.5, 0.7]) report('new', pNew, t);
  }
  console.log('\nlargest weights:');
  [...NAMES.keys()].sort((a, b) => Math.abs(w[b]) - Math.abs(w[a])).forEach((i) => console.log('  ' + NAMES[i].padEnd(18) + w[i].toFixed(2)));

  const vectors = ['https://ilearning.cycu.edu.tw/login/index.php', 'https://moodle.ntu.edu.tw/login/index.php', 'https://www.google.com',
    'http://185.220.101.45/login', 'http://secure-login.xyz/verify', 'https://yahoomaill.joxej972537483.workers.dev/', 'https://amazon-ploi.youdontcare.com/',
    'https://sg-connect01.firebaseapp.com/', 'http://www.acount-manager.info', 'http://uk-ensono.com', 'https://www.umc.org', 'https://www.dekopay.com',
    'https://user@evil-paypal.co.uk:8080/a?b=1', 'HTTP://WWW.Example.COM/X', 'https://github.com/user/repo', 'https://stackoverflow.com', 'https://good-looking-site.com/news',
    'https://www.my-company-portal.com', 'https://www.coca-cola.com', 'https://portal.nthu.edu.tw/account/login', 'https://www.bbc.co.uk']
    .map((url) => ({ url, probability: predict(url) }));
  console.log('\nsample predictions:'); vectors.forEach((v) => console.log('  ' + v.probability.toFixed(3) + '  ' + v.url));

  if (WRITE) {
    const model = { features: NAMES, mean: [...mean], scale: [...scale], coef: [...w].slice(0, F), intercept: w[F],
      sus_tld: SUS_TLD, free_hosts: FREE_HOSTS, brands: BRANDS, second_level: SECOND_LEVEL, institution: INSTITUTION_LIST,
      tld_prior: prior, tld_names: [...tldRate.keys()], tld_rates: [...tldRate.values()] };
    fs.writeFileSync(OUT, JSON.stringify(model, null, 1));
    fs.writeFileSync(path.join(__dirname, 'parity_vectors.json'), JSON.stringify(vectors, null, 1));
    console.log(`\nwrote ${OUT} and ml/parity_vectors.json`);
  }
}
main();
