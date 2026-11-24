// Where the Google (Web Risk) API key comes from, and the link checker built from it.
//
// Two modes:
//  - envFile given (the real server): the key lives in the .env file only. It is read from the file on
//    every request, and a key entered in the app is written into that file. Editing .env by hand works
//    too, with no restart. prism.db never holds the key (an old one is moved into .env at startup).
//  - no envFile (tests): a key saved from the app > WEB_RISK_API_KEY in the environment > none, kept in prism.db.
// The key can change while the server runs, so routes ask for the checker on every request.
// The full key is never sent back to anyone: status() only returns a masked hint.
import fs from 'node:fs';
import { config } from './config.js';
import { createWebRiskDetector, DetectorError } from './webrisk.js';
import { HttpError } from './errors.js';

const SETTING = 'web_risk_api_key';
const KEY_FORMAT = /^[A-Za-z0-9_-]{20,200}$/;   // Google API keys look like AIza + 35 characters
const PROBE_URL = 'https://example.com';

const mask = (key) => (key ? `${key.slice(0, 4)}...${key.slice(-4)}` : null);

const LINE = /^WEB_RISK_API_KEY=.*$/m;

/** The key written in the .env file: a string (maybe empty) when the line exists, null when it does not. */
function readEnvFile(file) {
  try {
    const m = fs.readFileSync(file, 'utf8').match(/^WEB_RISK_API_KEY=(.*?)\s*$/m);
    return m ? m[1].replace(/^["']|["']$/g, '') : null;
  } catch { return null; }
}

function writeEnvFile(file, key) {
  let text = '';
  try { text = fs.readFileSync(file, 'utf8'); } catch { /* no file yet: create it */ }
  const line = `WEB_RISK_API_KEY=${key}`;
  text = LINE.test(text) ? text.replace(LINE, () => line) : text + (text && !text.endsWith('\n') ? '\n' : '') + line + '\n';
  fs.writeFileSync(file, text);
}

export function createGoogleLink(db, { linkChecker = null, envKey = config.webRiskApiKey, makeDetector = createWebRiskDetector, envFile = null } = {}) {
  const read = db.prepare('SELECT value FROM settings WHERE key = ?');
  const write = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
  const remove = db.prepare('DELETE FROM settings WHERE key = ?');

  const stored = () => read.get(SETTING)?.value || '';
  let cached = { key: '', detector: null };

  // Move a key an older version saved in prism.db into .env, once.
  if (envFile && stored()) {
    if (!readEnvFile(envFile)) writeEnvFile(envFile, stored());
    remove.run(SETTING);
  }

  function activeKey() {
    if (envFile) {
      const key = readEnvFile(envFile) ?? envKey;   // the file wins whenever it has the line, even if empty
      return key ? { key, source: 'env' } : { key: '', source: 'none' };
    }
    const fromApp = stored();
    return fromApp ? { key: fromApp, source: 'app' } : envKey ? { key: envKey, source: 'env' } : { key: '', source: 'none' };
  }

  return {
    /** The link checker to use right now, or null when no key is set (the route then answers 503). */
    checker() {
      if (linkChecker) return linkChecker;   // injected by tests
      const { key } = activeKey();
      if (!key) return null;
      if (cached.key !== key) cached = { key, detector: makeDetector({ apiKey: key }) };
      return cached.detector;
    },

    /** { active, source: 'app' | 'env' | 'none' | 'test', hint } with the key masked ("AIza...x1Yz"). */
    status() {
      if (linkChecker) return { active: true, source: 'test', hint: null };
      const { key, source } = activeKey();
      return { active: !!key, source, hint: mask(key) };
    },

    /** Checks the key against Google first and saves it only if Google accepts it. */
    async setKey(raw) {
      const key = String(raw ?? '').trim();
      if (!KEY_FORMAT.test(key)) {
        throw new HttpError(400, 'invalid_key_format', 'That does not look like a Google API key (letters, digits, - and _, 20+ characters)');
      }
      try {
        await makeDetector({ apiKey: key }).checkUrl(PROBE_URL);
      } catch (e) {
        if (e instanceof DetectorError) {
          throw new HttpError(422, 'key_rejected', 'Google rejected this key. Check that the Web Risk API is enabled, billing is on, and the key is not restricted away from Web Risk');
        }
        throw new HttpError(502, 'cannot_verify', 'Could not reach Google to verify the key, so it was not saved. Try again');
      }
      if (envFile) writeEnvFile(envFile, key); else write.run(SETTING, key);
      return this.status();
    },

    /** Forget the key saved from the app (an environment key, if any, takes over). */
    clear() {
      if (envFile) writeEnvFile(envFile, ''); else remove.run(SETTING);
      return this.status();
    },
  };
}
