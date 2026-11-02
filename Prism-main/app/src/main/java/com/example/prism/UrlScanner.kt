package com.example.prism

/**
 * Local, offline URL scoring. This is a Kotlin port of `scanUrl()` in prism-backend/src/scanner.js
 * (same rules, weights and thresholds) so Manual Scan works without a network connection.
 * Keep the two files in sync when changing a rule.
 */
data class ScanReason(
    val rule: String,
    val detail: String,   // English, shown to the user
    val points: Int,
    val severity: String  // "high" | "medium" | "low"
)

data class UrlScanOutcome(
    val score: Int,
    val threat: ThreatLevel,
    val reasons: List<ScanReason>
)

object UrlScanner {
    // SAFE < 30, SUSPICIOUS (WARNING) 30..69, DANGEROUS (DANGER) >= 70
    const val WARNING_AT = 30
    const val DANGER_AT = 70

    private val SHORTENERS = setOf("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc")
    private val RISKY_TLDS = setOf("zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "support", "country", "kim", "loan", "men", "icu", "cyou", "rest", "online")
    private val URL_KEYWORDS = listOf("login", "signin", "verify", "secure", "account", "update", "wallet", "bank", "confirm", "password", "suspend", "unlock", "billing", "invoice", "refund")
    private val SECOND_LEVEL = setOf("co.uk", "org.uk", "com.au", "co.jp", "co.id", "com.tw", "com.br", "co.in", "com.sg", "com.cn", "com.hk", "co.nz")
    private val TRACKING_PARAMS = setOf("gclid", "fbclid", "msclkid", "dclid", "gbraid", "wbraid", "yclid", "ttclid", "twclid", "igshid", "mc_eid", "mc_cid", "gclsrc")
    private val RANDOM_TOKEN = Regex("[A-Za-z0-9_-]{51,}")
    private val TLD_LOOKALIKES = setOf("com", "net", "org", "gov", "edu")

    // brand label -> legitimate registrable domains
    private val BRANDS: Map<String, List<String>> = linkedMapOf(
        "paypal" to listOf("paypal.com"), "apple" to listOf("apple.com", "icloud.com"), "google" to listOf("google.com", "gmail.com"),
        "microsoft" to listOf("microsoft.com", "live.com", "office.com"), "amazon" to listOf("amazon.com"), "netflix" to listOf("netflix.com"),
        "facebook" to listOf("facebook.com"), "instagram" to listOf("instagram.com"), "whatsapp" to listOf("whatsapp.com"), "dhl" to listOf("dhl.com"),
        "fedex" to listOf("fedex.com"), "usps" to listOf("usps.com"), "chase" to listOf("chase.com"), "wellsfargo" to listOf("wellsfargo.com"),
        "bankofamerica" to listOf("bankofamerica.com"), "shopee" to listOf("shopee.com"), "line" to listOf("line.me"), "telkomsel" to listOf("telkomsel.com")
    )

    private val SCHEME_RE = Regex("^[a-zA-Z][a-zA-Z0-9+.-]*://")
    private val PARTS_RE = Regex("^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?#]*)([^?#]*)(.*)$")
    private val IPV4_RE = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private const val DOMAIN_RE = "(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,24}"
    private val DOMAIN_IN_TEXT = Regex("(?:https?://)?($DOMAIN_RE)(?![a-z0-9-])", RegexOption.IGNORE_CASE)
    private val AT_DOMAIN = Regex("@($DOMAIN_RE)", RegexOption.IGNORE_CASE)
    private val HTTP_PREFIX = Regex("^https?://", RegexOption.IGNORE_CASE)
    // Extensions that look like a domain ("report.pdf") but are just file names inside a query string.
    private val FILE_EXT = setOf("pdf", "png", "jpg", "jpeg", "gif", "svg", "webp", "html", "htm", "php", "asp", "aspx", "jsp", "js", "css", "json", "xml", "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "mp3", "mp4", "csv")

    internal data class Parsed(
        val https: Boolean,
        val hasUserInfo: Boolean,
        val host: String,
        val path: String,
        val query: String, // "?a=b#frag" (everything after the path)
        val length: Int
    )

    /** Pre-clean: trim the ends and drop whitespace inside the link (scan() flags inner whitespace). */
    private fun clean(raw: String): String = raw.trim().filterNot { it.isWhitespace() }

    /** Returns null when the text is not a usable http(s) address. Missing scheme is treated as http. */
    internal fun parse(raw: String): Parsed? {
        val t = clean(raw)
        if (t.isEmpty()) return null
        val withScheme = if (SCHEME_RE.containsMatchIn(t)) t else "http://$t"
        val m = PARTS_RE.find(withScheme) ?: return null
        val scheme = m.groupValues[1].lowercase()
        if (scheme != "http" && scheme != "https") return null
        val authority = m.groupValues[2]
        val hasUserInfo = authority.contains('@')
        val hostPort = authority.substringAfterLast('@') // the real host is the part AFTER the "@"
        val isV6 = hostPort.startsWith("[")
        val host = (if (isV6) hostPort.substringBefore(']') + "]" else hostPort.substringBefore(':')).lowercase()
        if (host.isEmpty()) return null
        if (!isV6 && !host.contains('.')) return null
        if (!isV6 && (host.startsWith(".") || host.endsWith(".") || host.contains(".."))) return null
        return Parsed(scheme == "https", hasUserInfo, host, m.groupValues[3].lowercase(), m.groupValues[4], withScheme.length)
    }

    /** True if [raw] can be scanned as a link (used by the UI to show a friendly message instead). */
    fun isValidUrl(raw: String): Boolean = parse(raw) != null

    private fun registrableDomain(host: String): String {
        val labels = host.split('.')
        if (labels.size <= 2) return host
        val lastTwo = labels.takeLast(2).joinToString(".")
        return if (lastTwo in SECOND_LEVEL) labels.takeLast(3).joinToString(".") else lastTwo
    }

    private fun levenshtein(a: String, b: String): Int {
        val dp = Array(a.length + 1) { i -> IntArray(b.length + 1).also { it[0] = i } }
        for (j in 1..b.length) dp[0][j] = j
        for (i in 1..a.length) for (j in 1..b.length) {
            dp[i][j] = minOf(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + if (a[i - 1] == b[j - 1]) 0 else 1)
        }
        return dp[a.length][b.length]
    }

    private fun severityOf(points: Int) = if (points >= 35) "high" else if (points >= 15) "medium" else "low"
    private fun rank(severity: String) = when (severity) { "high" -> 3; "medium" -> 2; else -> 1 }

    private fun finish(reasons: List<ScanReason>): UrlScanOutcome {
        val score = minOf(100, reasons.sumOf { it.points })
        val threat = when {
            score >= DANGER_AT -> ThreatLevel.DANGER
            score >= WARNING_AT -> ThreatLevel.WARNING
            else -> ThreatLevel.SAFE
        }
        val sorted = reasons.sortedWith(compareByDescending<ScanReason> { rank(it.severity) }.thenByDescending { it.points })
        return UrlScanOutcome(score, threat, sorted)
    }

    private fun mk(rule: String, points: Int, detail: String) = ScanReason(rule, detail, points, severityOf(points))

    private fun safeDecode(s: String): String =
        try { java.net.URLDecoder.decode(s.replace("+", "%2B"), "UTF-8") } catch (e: Exception) { s }

    private data class Hidden(val host: String, val domain: String, val strong: Boolean)

    /** Other domains hidden in the query string / fragment. strong = starts a parameter value or has a scheme. */
    private fun findHidden(query: String, frontDomain: String): List<Hidden> {
        val text = safeDecode(query)
        val found = mutableListOf<Hidden>()
        for (m in DOMAIN_IN_TEXT.findAll(text)) {
            val host = m.groupValues[1].lowercase()
            if (host.substringAfterLast('.') in FILE_EXT) continue
            val prev = text.getOrNull(m.range.first - 1)
            if (prev == '@') continue // handled by the "@" rule
            val domain = registrableDomain(host)
            if (domain == frontDomain || found.any { it.domain == domain }) continue
            found += Hidden(host, domain, prev == '=' || HTTP_PREFIX.containsMatchIn(m.value))
        }
        return found
    }

    /** Scores ONE host (the visible one, or one hidden inside the URL). checkHttps=false for hidden hosts. */
    private fun scoreHost(p: Parsed, advanced: Boolean, blocklist: Set<String>, checkHttps: Boolean): List<ScanReason> {
        val reasons = mutableListOf<ScanReason>()
        fun add(rule: String, points: Int, detail: String) { reasons += mk(rule, points, detail) }

        val host = p.host
        val domain = registrableDomain(host)
        val tld = domain.substringAfterLast('.')
        val hostLabels = host.split('.')
        // A known brand's own domain (e.g. accounts.google.com) is trusted: skip wording/brand checks.
        val trusted = BRANDS.values.any { domain in it }

        if (host in blocklist || domain in blocklist) add("blocklisted", 100, "Reported as malicious by other users")
        if (IPV4_RE.matches(host) || host.startsWith("[")) add("ip_host", 40, "Uses a raw IP address instead of a domain name; legitimate sites rarely do this")
        if (p.hasUserInfo) add("userinfo", 35, "Uses an @ sign to hide the real domain")
        if (hostLabels.any { it.startsWith("xn--") }) add("punycode", 30, "Domain uses look-alike special characters and may be impersonating another site")
        if (checkHttps && !p.https) add("no_https", 10, "Connection is not encrypted (HTTP); data you enter could be intercepted")
        if (tld in RISKY_TLDS) add("risky_tld", 20, ".$tld domains are frequently abused")

        // "plurebo.com.evil.online": a .com/.net label placed before the real domain to look official.
        val before = hostLabels.take(hostLabels.size - domain.split('.').size)
        val fakeTld = before.firstOrNull { it in TLD_LOOKALIKES }
        if (fakeTld != null) add("fake_tld_label", 25, "Looks like it ends in .$fakeTld, but the real domain is $domain")

        if (hostLabels.size >= 5) add("deep_subdomain", 15, "Unusually many subdomain levels")
        if (domain in SHORTENERS) add("shortener", 15, "Link shortener hides the real destination")

        // Sensitive wording: strong in the domain/subdomain, weak in the path, so one word in a path
        // (e.g. /account) can never reach DANGEROUS by itself.
        val hostKw = if (trusted) emptyList() else URL_KEYWORDS.filter { host.contains(it) }
        val pathKw = if (trusted) emptyList() else URL_KEYWORDS.filter { it !in hostKw && p.path.contains(it) }
        if (hostKw.isNotEmpty()) {
            add("keywords_host", minOf(35, hostKw.size * 15), "Sensitive wording in the domain (${hostKw.take(3).joinToString(", ")}), common on fake login or verification pages")
        }
        if (pathKw.isNotEmpty()) {
            add("keywords_path", minOf(6, pathKw.size * 3), "Sensitive wording in the path (${pathKw.take(3).joinToString(", ")})")
        }
        if (host.count { it == '-' } >= 3) add("hyphens", 10, "Too many hyphens in the domain")
        // URL length is NEUTRAL-to-bad: it can only add points, never lower the score or count as "safe".
        if (p.length > 100) add("long_url", 5, "Unusually long address")
        // Tracking parameters (gclid, utm_*, fbclid...) are real only as "?gclid=..." in the query string.
        // As a folder/segment of the PATH ("/gclid/=/c/") they are a common fake-ad / cloaking trick.
        val trackingInPath = p.path.split('/').map { safeDecode(it).lowercase().substringBefore('=') }
            .any { it in TRACKING_PARAMS || it.startsWith("utm_") }
        if (trackingInPath) add("tracking_in_path", 30, "Tracking parameter appears in the URL path (possibly forged)")
        // One very long random-looking token (>50 chars, letters and digits) in the query.
        if (RANDOM_TOKEN.findAll(p.query).any { t -> t.value.any { it.isDigit() } && t.value.any { it.isLetter() } }) {
            add("random_query_token", 10, "Unusually long random-looking parameter")
        }
        // HONEST LIMIT: a genuinely clean-looking domain (HTTPS, common TLD, no keywords, not a brand
        // look-alike) can still be phishing and will score SAFE. That is a limit of local heuristics,
        // not a bug; catching it needs a Gemini layer or threat intelligence.

        // Brand impersonation: the brand must be a whole label, or a whole "-"-separated part of a label
        // ("paypal-login" matches, "airline"/"pineapple" do not match "line"/"apple").
        if (!trusted) {
            for ((brand, legit) in BRANDS) {
                val labelHasBrand = { l: String -> l == brand || l.split('-').contains(brand) }
                val mentionsBrand = hostLabels.any(labelHasBrand) ||
                    (p.path.contains(brand) && (hostKw.isNotEmpty() || pathKw.isNotEmpty()))
                if (mentionsBrand && domain !in legit) {
                    add("brand_impersonation", 40, "Appears to impersonate $brand but is not the official site")
                    break
                }
                if (advanced) {
                    val label = domain.substringBefore('.').map { c ->
                        when (c) { '0' -> 'o'; '1' -> 'l'; '3' -> 'e'; '5' -> 's'; else -> c }
                    }.joinToString("")
                    if (label != brand && brand.length >= 5 && levenshtein(label, brand) <= 1) {
                        add("typosquat", 45, "Domain closely mimics $brand (possible typo-squatting)")
                        break
                    }
                }
            }
        }
        return reasons
    }

    /**
     * @param advanced extra typosquat detection (Prism Plus only, same as the backend plan rule)
     * @param blocklist hosts/domains known to be malicious
     */
    fun scan(raw: String, advanced: Boolean = false, blocklist: Set<String> = emptySet()): UrlScanOutcome {
        val p = parse(raw) ?: return finish(listOf(mk("invalid_url", 30, "Not a valid web address")))
        val frontDomain = registrableDomain(p.host)

        // Rules about the URL as a whole: they apply to the visible host AND to every hidden one.
        val context = mutableListOf<ScanReason>()
        if (raw.trim().any { it.isWhitespace() }) context += mk("whitespace", 15, "Contains whitespace, possibly tampered with")
        // An "@" outside the host part (path/query): the text after it looks like the destination.
        val atHost = if (p.hasUserInfo) null
            else AT_DOMAIN.find(safeDecode(p.path + p.query))?.groupValues?.get(1)?.lowercase()
        if (atHost != null) context += mk("at_sign", 35, "Uses an @ sign to hide the real domain")
        val hidden = findHidden(p.query, frontDomain)
        if (hidden.isNotEmpty()) {
            context += mk("embedded_url", if (hidden.any { it.strong }) 30 else 15,
                "Another domain is hidden inside the address (possible redirect scam): ${hidden.joinToString(", ") { it.domain }}")
        }

        // The WORST host decides the verdict, so a clean front domain can't cover for a hidden bad one.
        var worst = scoreHost(p, advanced, blocklist, checkHttps = true)
        for (h in (hidden.map { it.host } + listOfNotNull(atHost)).distinct()) {
            val hp = parse("https://$h") ?: continue
            val own = scoreHost(hp, advanced, blocklist, checkHttps = false).map { it.copy(detail = "($h) ${it.detail}") }
            if (own.sumOf { it.points } > worst.sumOf { it.points }) worst = own
        }

        val reasons = (context + worst).toMutableList()
        // Nothing found -> give the SAFE popup a neutral positive reason instead of an empty list.
        if (reasons.isEmpty()) reasons += mk("no_issues", 0, "No obvious suspicious features (uses HTTPS, normal domain structure)")
        return finish(reasons)
    }
}
