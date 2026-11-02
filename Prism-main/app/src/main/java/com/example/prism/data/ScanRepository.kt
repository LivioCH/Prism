package com.example.prism.data

import com.example.prism.ScanReason
import com.example.prism.ScanType
import com.example.prism.ThreatLevel
import com.example.prism.scan.ManualScanAnalyzer
import com.example.prism.scan.ManualScanOutcome
import org.json.JSONArray
import org.json.JSONObject

/** Where a Manual Scan result came from. */
enum class ScanSource { BLACKLIST, WHITELIST, CACHE, FRESH }

data class RepoScanResult(val outcome: ManualScanOutcome, val source: ScanSource)

/** Normalisation shared by whitelist and cache lookups. */
object UrlKeys {
    private val SCHEME = Regex("^[a-z][a-z0-9+.-]*://")

    private fun clean(raw: String) = raw.trim().filterNot { it.isWhitespace() }

    /** Host of a URL, lower-case, no "www.", no port / userinfo ("a.com@evil.com" -> "evil.com"). */
    fun host(raw: String): String? {
        var h = clean(raw).lowercase().replace(SCHEME, "")
        h = h.substringBefore('/').substringBefore('?').substringBefore('#')
        h = h.substringAfterLast('@').substringBefore(':').removePrefix("www.")
        return h.ifEmpty { null }
    }

    /** Cache key: the whole URL, lower-case, without whitespace, fragment or trailing slash. */
    fun cacheKey(raw: String): String = clean(raw).substringBefore('#').lowercase().trimEnd('/')
}

/** ScanReason list <-> JSON text stored in the database. */
object ReasonsJson {
    fun encode(reasons: List<ScanReason>): String {
        val arr = JSONArray()
        reasons.forEach {
            arr.put(JSONObject().put("rule", it.rule).put("detail", it.detail).put("points", it.points).put("severity", it.severity))
        }
        return arr.toString()
    }

    fun decode(json: String): List<ScanReason> = runCatching {
        val arr = JSONArray(json)
        (0 until arr.length()).map {
            val o = arr.getJSONObject(it)
            ScanReason(o.getString("rule"), o.getString("detail"), o.optInt("points"), o.optString("severity", "low"))
        }
    }.getOrDefault(emptyList())
}

/** DB text <-> app enums. The DB speaks SAFE / SUSPICIOUS / DANGEROUS and URL / TEXT / PHONE. */
object DbMap {
    fun verdict(t: ThreatLevel) = when (t) { ThreatLevel.SAFE -> "SAFE"; ThreatLevel.WARNING -> "SUSPICIOUS"; ThreatLevel.DANGER -> "DANGEROUS" }
    fun threat(v: String) = when (v) { "DANGEROUS" -> ThreatLevel.DANGER; "SUSPICIOUS" -> ThreatLevel.WARNING; else -> ThreatLevel.SAFE }
    fun kind(t: ScanType) = when (t) { ScanType.URL -> "URL"; ScanType.MESSAGE -> "TEXT"; ScanType.PHONE -> "PHONE" }
    fun type(k: String) = when (k) { "URL" -> ScanType.URL; "PHONE" -> ScanType.PHONE; else -> ScanType.MESSAGE }
}

/**
 * The full Manual Scan pipeline, in this exact order:
 *   1 normalise -> 2 BLACKLIST -> 3 whitelist -> 4 cache -> 5 heuristics + ML -> 6 save (cache + history).
 * The blacklist is checked first and beats everything else. Every path ends in the history table.
 * Blacklist, whitelist and cache only apply to URL input; text and phone input always go to the
 * analyzer (which still flags blacklisted URLs found inside a message, see blacklistValues()).
 */
class ScanRepository(
    private val history: ScanHistoryDao,
    private val whitelist: WhitelistDao,
    private val blacklist: BlacklistDao,
    private val cache: UrlCacheDao,
    private val now: () -> Long = System::currentTimeMillis
) {
    companion object {
        /** A cached verdict older than this is analysed again (blocklists and rules change). */
        const val CACHE_TTL_MS = 7L * 24 * 60 * 60 * 1000
        const val BLOCKED_REASON = "You blocked this site"
        const val TRUSTED_REASON = "You trust this site"
        const val CACHE_REASON = "Result from cache"
    }

    suspend fun scan(input: String, analyze: (String) -> ManualScanOutcome): RepoScanResult {
        val text = input.trim()                                          // 1. normalise
        val kind = ManualScanAnalyzer.detectKind(text)
        var source = ScanSource.FRESH
        var outcome: ManualScanOutcome? = null

        if (kind == ScanType.URL) {
            val host = UrlKeys.host(text)
            val key = UrlKeys.cacheKey(text)

            if (host != null && blacklist.countMatches(listOf(host, key)) > 0) {   // 2. blacklist FIRST, beats all
                outcome = ManualScanOutcome(
                    kind = ScanType.URL,
                    threat = ThreatLevel.DANGER,
                    reasons = listOf(ScanReason("blacklisted", BLOCKED_REASON, 100, "high")),
                    infoLines = emptyList()
                )
                source = ScanSource.BLACKLIST
            } else if (host != null && whitelist.countMatches(listOf(host, key)) > 0) {   // 3. whitelist
                outcome = ManualScanOutcome(
                    kind = ScanType.URL,
                    threat = ThreatLevel.SAFE,
                    reasons = listOf(ScanReason("whitelisted", TRUSTED_REASON, 0, "low")),
                    infoLines = emptyList()
                )
                source = ScanSource.WHITELIST
            } else {
                val hit = cache.get(key)?.takeIf { now() - it.cachedAt < CACHE_TTL_MS }   // 4. cache
                if (hit != null) {
                    val ml = hit.mlScore
                    outcome = ManualScanOutcome(
                        kind = ScanType.URL,
                        threat = DbMap.threat(hit.verdict),
                        reasons = listOf(ScanReason("from_cache", CACHE_REASON, 0, "low")) + ReasonsJson.decode(hit.reasons),
                        infoLines = if (ml != null) listOf("ML: ${ManualScanAnalyzer.percent(ml)}% phishing probability") else emptyList()
                    )
                    source = ScanSource.CACHE
                }
            }
        }

        val result = outcome ?: analyze(text)                            // 5. heuristics + ML (unchanged)

        if (source == ScanSource.FRESH && kind == ScanType.URL) {        // 6a. remember it
            cache.put(
                UrlCacheEntity(
                    key = UrlKeys.cacheKey(text),
                    verdict = DbMap.verdict(result.threat),
                    mlScore = mlScoreOf(result),
                    reasons = ReasonsJson.encode(result.reasons),
                    cachedAt = now()
                )
            )
        }
        history.insert(                                                  // 6b. history, on EVERY path
            ScanHistoryEntity(
                input = text,
                kind = DbMap.kind(result.kind),
                verdict = DbMap.verdict(result.threat),
                mlScore = mlScoreOf(result),
                reasons = ReasonsJson.encode(result.reasons),
                timestamp = now()
            )
        )
        return RepoScanResult(result, source)
    }

    /** Highest ML probability among the URLs that were scored (null when no ML ran). */
    private fun mlScoreOf(o: ManualScanOutcome): Double? = o.urlResults.mapNotNull { it.mlProbability }.maxOrNull()

    /**
     * Trust a URL's host. Returns false if the URL has no usable host.
     * A host is never on both lists: trusting it removes it from the blacklist.
     */
    suspend fun trust(urlOrHost: String): Boolean {
        val host = UrlKeys.host(urlOrHost) ?: return false
        blacklist.delete(host)
        whitelist.insert(WhitelistEntity(value = host, createdAt = now()))
        return true
    }

    suspend fun untrust(value: String) = whitelist.delete(value)

    /** Block a URL's host (always DANGEROUS from now on). Blocking removes it from the whitelist. */
    suspend fun block(urlOrHost: String): Boolean {
        val host = UrlKeys.host(urlOrHost) ?: return false
        whitelist.delete(host)
        blacklist.insert(BlacklistEntity(value = host, createdAt = now()))
        return true
    }

    suspend fun unblock(value: String) = blacklist.delete(value)

    /**
     * Blocked hosts, handed to the heuristic scanner so its existing "blocklisted" rule also fires
     * for blocked URLs found inside a text message.
     */
    suspend fun blacklistValues(): Set<String> = blacklist.allValues().toSet()
}
