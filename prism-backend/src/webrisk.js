// Google Cloud Web Risk API, Lookup (uris.search): https://cloud.google.com/web-risk/docs/lookup-api
// Checks links against Google's lists of phishing, malware and unwanted-software sites.
// The API key stays on the server; the app only talks to POST /api/scans/webrisk.
// Any failure throws, so a broken check can never be reported as "safe".

export class DetectorError extends Error {}

export const THREAT_TYPES = ['SOCIAL_ENGINEERING', 'MALWARE', 'UNWANTED_SOFTWARE'];
const LABELS = { SOCIAL_ENGINEERING: 'phishing', MALWARE: 'malware', UNWANTED_SOFTWARE: 'unwanted software' };
export const threatLabel = (type) => LABELS[type] ?? type.toLowerCase();

const MAX_LINKS = 10;
// Web addresses with or without "http(s)://", e.g. "https://a.com/x", "www.a.com", "a-b.xyz/login".
const LINK_RE = /(?<![\w@.-])(?:https?:\/\/)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}(?::\d{1,5})?(?:[/?#][^\s<>"']*)?/gi;
// "report.pdf" looks like a domain but is a file name
const FILE_EXT = new Set(['pdf', 'png', 'jpg', 'jpeg', 'gif', 'txt', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'mp3', 'mp4', 'csv', 'json', 'html', 'htm', 'md', 'js', 'css']);
const TRAILING = /[.,;:!?)\]}'"]+$/;

/** Links found in [text], with "http://" added when missing. At most 10, no duplicates. */
export function extractLinks(text) {
  const links = [];
  for (const m of text.matchAll(LINK_RE)) {
    const raw = m[0].replace(TRAILING, '');
    const hasScheme = /^https?:\/\//i.test(raw);
    const host = raw.replace(/^https?:\/\//i, '').split(/[/?#:]/)[0];
    if (!hasScheme && !raw.includes('/') && FILE_EXT.has(host.split('.').pop().toLowerCase())) continue;
    const url = hasScheme ? raw : `http://${raw}`;
    if (!links.includes(url)) links.push(url);
    if (links.length >= MAX_LINKS) break;
  }
  return links;
}

export function createWebRiskDetector({ apiKey, baseUrl = 'https://webrisk.googleapis.com', fetchImpl = fetch, timeoutMs = 15_000 }) {
  return {
    /** { url, threatTypes } where threatTypes is empty when the URL is on none of Google's lists. */
    async checkUrl(url) {
      const params = new URLSearchParams();
      for (const t of THREAT_TYPES) params.append('threatTypes', t);
      params.append('uri', url);
      params.append('key', apiKey);
      const res = await fetchImpl(`${baseUrl}/v1/uris:search?${params}`, { signal: AbortSignal.timeout(timeoutMs) });
      if (!res.ok) throw new DetectorError(`Web Risk returned ${res.status}`);
      const body = await res.json();
      if (body === null || typeof body !== 'object') throw new DetectorError('Web Risk sent an unexpected response');
      if (body.threat === undefined) return { url, threatTypes: [] };   // "{}" means no match
      if (!Array.isArray(body.threat.threatTypes)) throw new DetectorError('Web Risk sent an unexpected response');
      return { url, threatTypes: body.threat.threatTypes };
    },
  };
}
