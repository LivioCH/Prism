package com.example.prism.scan

import com.example.prism.ScanReason
import com.example.prism.ScanType
import com.example.prism.ThreatLevel
import com.example.prism.UrlScanner

/** What Manual Scan found. Texts are English. */
data class ManualScanOutcome(
    val kind: ScanType,                 // detected input kind: URL, MESSAGE (text) or PHONE
    val threat: ThreatLevel,
    val reasons: List<ScanReason>,
    val infoLines: List<String>,        // "ML: 83% phishing probability", notes about how the verdict was made
    val urlResults: List<UrlResult> = emptyList()
)

data class UrlResult(val url: String, val mlProbability: Double?, val threat: ThreatLevel, val reasons: List<ScanReason>)

/**
 * Single entry point of Manual Scan. Detects the input kind by itself:
 *  - one URL        -> ML model + old heuristic scanner, worst verdict wins
 *  - text/message   -> every URL inside is scored like above, plus scam-wording signals
 *  - phone number   -> heuristic rules ONLY (there is no ML dataset for phone numbers)
 * Everything is offline.
 */
object ManualScanAnalyzer {
    private val PHONE_RE = Regex("^\\+?[0-9\\s\\-()]+$")
    private val IPV4_RE = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private val URL_IN_TEXT = Regex(
        "(?:https?://|www\\.)[^\\s<>\"'，。、「」]+|\\b[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.[a-z]{2,24}/[^\\s<>\"'，。、「」]*",
        RegexOption.IGNORE_CASE
    )
    private const val TRAILING = ".,;:!?)）。，、；：！？」"

    /** Common scam wording (Traditional Chinese). Each distinct word adds [WORD_POINTS]. */
    internal val SCAM_WORDS = listOf(
        "中獎", "急", "驗證", "帳號異常", "帳戶異常", "點擊連結", "立即", "凍結", "停用",
        "領取", "退款", "補貼", "匯款", "轉帳", "限時", "包裹"
    )
    private const val WORD_POINTS = 15
    private const val WARNING_AT = 30
    private const val DANGER_AT = 70

    fun detectKind(input: String): ScanType {
        val t = input.trim()
        if (t.isEmpty()) return ScanType.MESSAGE
        if (!IPV4_RE.matches(t) && PHONE_RE.matches(t) && t.count { it.isDigit() } >= 3) return ScanType.PHONE
        // A link may contain spaces (a trick we flag), so a leading scheme is enough to call it a URL.
        if (Regex("^https?://", RegexOption.IGNORE_CASE).containsMatchIn(t)) return ScanType.URL
        if (t.none { it.isWhitespace() } && UrlScanner.isValidUrl(t)) return ScanType.URL
        return ScanType.MESSAGE
    }

    fun analyze(input: String, model: UrlMlModel?, advanced: Boolean = false, blocklist: Set<String> = emptySet()): ManualScanOutcome =
        when (detectKind(input)) {
            ScanType.PHONE -> analyzePhone(input.trim())
            ScanType.URL -> analyzeSingleUrl(input.trim(), model, advanced, blocklist)
            ScanType.MESSAGE -> analyzeText(input.trim(), model, advanced, blocklist)
        }

    // ---------------------------------------------------------------- URL

    private fun rank(t: ThreatLevel) = when (t) { ThreatLevel.SAFE -> 0; ThreatLevel.WARNING -> 1; ThreatLevel.DANGER -> 2 }
    private fun worse(a: ThreatLevel, b: ThreatLevel) = if (rank(a) >= rank(b)) a else b
    private fun sevRank(s: String) = when (s) { "high" -> 3; "medium" -> 2; else -> 1 }
    private fun sorted(r: List<ScanReason>) = r.sortedWith(compareByDescending<ScanReason> { sevRank(it.severity) }.thenByDescending { it.points })

    private fun mlThreat(p: Double) = when {
        p >= UrlMlModel.DANGEROUS_AT -> ThreatLevel.DANGER
        p >= UrlMlModel.SUSPICIOUS_AT -> ThreatLevel.WARNING
        else -> ThreatLevel.SAFE
    }

    fun percent(p: Double) = Math.round(p * 100).toInt()

    /** ML + old heuristics for one URL. Final verdict = the more dangerous of the two. */
    internal fun evaluateUrl(url: String, model: UrlMlModel?, advanced: Boolean, blocklist: Set<String> = emptySet()): UrlResult {
        val heuristic = UrlScanner.scan(url, advanced, blocklist)
        val p = model?.predict(url.trim().filterNot { it.isWhitespace() })
        val mlT = if (p == null) ThreatLevel.SAFE else mlThreat(p)
        val threat = worse(heuristic.threat, mlT)
        var reasons = heuristic.reasons
        // The "nothing found" reason must not stay next to a warning raised by the ML model.
        if (threat != ThreatLevel.SAFE) reasons = reasons.filter { it.rule != "no_issues" }
        if (p != null && mlT != ThreatLevel.SAFE) {
            reasons = reasons + ScanReason(
                "ml_model", "The machine-learning model rates this address ${percent(p)}% likely to be phishing", percent(p),
                if (mlT == ThreatLevel.DANGER) "high" else "medium"
            )
        }
        return UrlResult(url, p, threat, sorted(reasons))
    }

    private fun analyzeSingleUrl(url: String, model: UrlMlModel?, advanced: Boolean, blocklist: Set<String>): ManualScanOutcome {
        val r = evaluateUrl(url, model, advanced, blocklist)
        val info = if (r.mlProbability != null) listOf("ML: ${percent(r.mlProbability)}% phishing probability") else emptyList()
        return ManualScanOutcome(ScanType.URL, r.threat, r.reasons, info, listOf(r))
    }

    // ---------------------------------------------------------------- text

    internal fun extractUrls(text: String): List<String> =
        URL_IN_TEXT.findAll(text).map { it.value.trimEnd { c -> c in TRAILING } }.filter { it.isNotEmpty() }.distinct().toList()

    private fun shortHost(url: String) = url.substringAfter("://").substringBefore('/').substringBefore('?').take(40)

    private fun analyzeText(text: String, model: UrlMlModel?, advanced: Boolean, blocklist: Set<String>): ManualScanOutcome {
        val urls = extractUrls(text)
        val results = urls.map { evaluateUrl(it, model, advanced, blocklist) }
        val info = mutableListOf<String>()
        val reasons = mutableListOf<ScanReason>()

        // Scam wording in the message itself
        val hits = SCAM_WORDS.filter { text.contains(it) }
        val wordPoints = minOf(100, hits.size * WORD_POINTS)
        var threat = when {
            wordPoints >= DANGER_AT -> ThreatLevel.DANGER
            wordPoints >= WARNING_AT -> ThreatLevel.WARNING
            else -> ThreatLevel.SAFE
        }
        if (hits.isNotEmpty()) {
            reasons += ScanReason("scam_words", "Message contains common scam wording: ${hits.take(5).joinToString(", ")}", wordPoints,
                if (wordPoints >= 35) "high" else if (wordPoints >= 15) "medium" else "low")
        }

        info += if (urls.isEmpty()) "No URLs found in the message" else "Found ${urls.size} URL(s) in the message"
        for (r in results) {
            threat = worse(threat, r.threat)
            val h = shortHost(r.url)
            if (r.mlProbability != null) info += "ML: ${percent(r.mlProbability)}% phishing probability ($h)"
            for (x in r.reasons) if (x.rule != "no_issues") reasons += x.copy(detail = "($h) ${x.detail}")
        }
        if (hits.size >= 2 && results.any { it.threat != ThreatLevel.SAFE }) {
            threat = ThreatLevel.DANGER
            reasons += ScanReason("scam_words_with_link", "Scam wording combined with a suspicious link: very dangerous", 40, "high")
        }
        if (reasons.isEmpty()) {
            reasons += ScanReason("no_issues", "No obvious suspicious features (no suspicious URLs or common scam wording)", 0, "low")
        }
        return ManualScanOutcome(ScanType.MESSAGE, threat, sorted(reasons), info, results)
    }

    // ---------------------------------------------------------------- phone

    // Calling codes that are common for real contacts
    private val COMMON_CODES = setOf("1", "7", "20", "27", "30", "31", "32", "33", "34", "39", "41", "43", "44", "45", "46", "47", "48", "49",
        "52", "54", "55", "56", "60", "61", "62", "63", "64", "65", "66", "81", "82", "84", "86", "91", "92", "94", "852", "853", "886", "971")
    // Codes often used in "one ring" / callback scams
    private val RISKY_CODES = setOf("225", "232", "234", "236", "242", "243", "252", "257", "375", "592", "809", "876")

    private fun callingCode(digits: String): String? =
        (3 downTo 1).map { digits.take(it) }.firstOrNull { it in COMMON_CODES || it in RISKY_CODES }

    private fun analyzePhone(raw: String): ManualScanOutcome {
        val reasons = mutableListOf<ScanReason>()
        fun add(rule: String, pts: Int, detail: String) {
            reasons += ScanReason(rule, detail, pts, if (pts >= 35) "high" else if (pts >= 15) "medium" else "low")
        }
        var digits = raw.filter { it.isDigit() }
        var international = raw.startsWith("+")
        if (!international && digits.startsWith("00")) { international = true; digits = digits.drop(2) }

        if (digits.length < 7) add("too_short", 30, "Number is too short (only ${digits.length} digits)")
        if (digits.length > 15) add("too_long", 30, "Number is too long (${digits.length} digits), beyond the international standard")
        if (international && digits.length >= 4) {
            val code = callingCode(digits)
            when {
                code != null && code in RISKY_CODES -> add("risky_country", 25, "Country code +$code is common in callback scams (one ring, then hang up)")
                code == null -> add("unusual_country", 25, "Unusual country code +${digits.take(3)}, be careful")
            }
        }
        if (Regex("(\\d)\\1{5,}").containsMatchIn(digits)) add("repeated_digits", 15, "Number has repeated digits in a row")
        val asc = "0123456789"
        if ((0..digits.length - 6).any { i -> digits.substring(i, i + 6).let { it in asc || it.reversed() in asc } }) {
            add("sequential_digits", 15, "Number has sequential digits")
        }
        if (reasons.isEmpty()) add("no_issues", 0, "No obvious suspicious features (normal length and format)")

        val score = minOf(100, reasons.sumOf { it.points })
        val threat = when {
            score >= 60 -> ThreatLevel.DANGER
            score >= 25 -> ThreatLevel.WARNING
            else -> ThreatLevel.SAFE
        }
        return ManualScanOutcome(ScanType.PHONE, threat, sorted(reasons), listOf("Phone number checks use heuristic rules only, not an official database"))
    }
}
