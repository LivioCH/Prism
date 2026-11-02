export const publicUser = (u) => ({
  id: u.id,
  name: u.name,
  email: u.email,
  plan: u.plan,                                  // "FREE" | "PLUS" | null (=> show plan picker)
  clipboardMonitoring: !!u.clipboard_monitoring,
  createdAt: u.created_at,
});

// Lowercase enums + epoch-ms `timestamp` match what the Kotlin UI models consume
// (ScanHistoryItem.type/threat are lowercase strings).
export const publicScan = (s) => ({
  id: s.id,
  type: s.type.toLowerCase(),
  threat: s.threat.toLowerCase(),
  content: s.content,
  details: s.details,
  score: s.score,
  source: s.source,
  timestamp: s.created_at,
});
