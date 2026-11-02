package com.example.prism.scan

import com.example.prism.ScanReason
import com.example.prism.ScanType
import com.example.prism.ThreatLevel
import com.example.prism.UrlScanner

/** What Manual Scan found. URL reasons are English; phone and scam-wording reasons are Traditional Chinese. */
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
 *  - phone number   -> PhoneAnalyzer (libphonenumber for every country + home-region signals), no ML
 * Everything is offline.
 */
object ManualScanAnalyzer {
    private val PHONE_RE = Regex("^\\+?[0-9\\s\\-()]+$")
    private val MALFORMED_PHONE_RE = Regex("^[A-Za-z0-9+()\\-]+$")
    private val IPV4_RE = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private val URL_IN_TEXT = Regex(
        "(?:https?://|www\\.)[^\\s<>\"'，。、「」]+|\\b[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.[a-z]{2,24}/[^\\s<>\"'，。、「」]*",
        RegexOption.IGNORE_CASE
    )
    private const val TRAILING = ".,;:!?)）。，、；：！？」"

    /** How much a scam-wording category weighs: a single WEAK category can never be DANGEROUS on its own. */
    internal enum class Weight(val points: Int) { WEAK(10), MEDIUM(15), HIGH(20) }

    /**
     * One group of Traditional-Chinese scam wording. To widen detection just add phrases to a list below;
     * the scoring logic in [analyzeText] does not need to change.
     */
    internal data class ScamCategory(val rule: String, val label: String, val weight: Weight, val phrases: List<String>)

    // Bilingual phrase lists (Traditional Chinese + English). English phrases are matched case-insensitively
    // on whole words only; Chinese phrases are matched as plain substrings. Add phrases here, no logic change needed.
    internal val URGENCY = ScamCategory("scam_urgency", "Urgency", Weight.WEAK, listOf(
        "立即", "馬上", "盡快", "24小時", "逾期", "緊急", "最後通知", "限時",
        "immediately", "act now", "expires today", "expire today", "within 24 hours", "urgent", "final notice",
        "will be locked", "suspended", "limited time"))
    internal val ACCOUNT_THREAT = ScamCategory("scam_account_threat", "Account threat", Weight.HIGH, listOf(
        "帳號異常", "帳號凍結", "帳號將被凍結", "帳號停用", "身分驗證", "重新驗證", "資料過期",
        "unauthorized sign-in", "unusual activity", "verify your identity", "account will be locked",
        "account suspended", "confirm your account", "security alert"))
    internal val PRIZE_BAIT = ScamCategory("scam_prize_bait", "Prize bait", Weight.HIGH, listOf(
        "中獎", "得獎", "免費領取", "抽中", "紅包",
        "you won", "congratulations", "claim your prize", "free gift", "you have been selected"))
    internal val MONEY = ScamCategory("scam_money", "Money request", Weight.HIGH, listOf(
        "退款", "退稅", "匯款", "轉帳", "補繳", "手續費", "解除分期", "保證金",
        "refund", "payment", "billing", "renew", "overdue", "wire transfer", "processing fee", "tax refund"))
    internal val CREDENTIALS = ScamCategory("scam_credentials", "Credentials/links", Weight.HIGH, listOf(
        "點擊連結", "請登入", "驗證碼", "輸入密碼", "輸入OTP", "更新付款",
        "click here", "verify", "log in", "security code", "one-time code", "update your payment", "confirm password"))
    internal val PARCEL = ScamCategory("scam_parcel", "Parcel/delivery", Weight.MEDIUM, listOf(
        "包裹", "無法配送", "地址有誤", "重新配送", "補件", "清關費",
        "package", "delivery failed", "redelivery", "customs fee", "track your parcel"))

    internal val SCAM_CATEGORIES = listOf(URGENCY, ACCOUNT_THREAT, PRIZE_BAIT, MONEY, CREDENTIALS, PARCEL)
    private const val EXTRA_PHRASE_POINTS = 5  // each further matching phrase of the same category (max 2)

    fun detectKind(input: String): ScanType {
        val t = input.trim()
        if (t.isEmpty()) return ScanType.MESSAGE
        if (!IPV4_RE.matches(t) && PHONE_RE.matches(t) && t.count { it.isDigit() } >= 3) return ScanType.PHONE
        // A link may contain spaces (a trick we flag), so a leading scheme is enough to call it a URL.
        if (Regex("^https?://", RegexOption.IGNORE_CASE).containsMatchIn(t)) return ScanType.URL
        if (t.none { it.isWhitespace() } && UrlScanner.isValidUrl(t)) return ScanType.URL
        // One token that is mostly digits but has letters mixed in ("abc123") is a malformed phone number, not a message
        if (MALFORMED_PHONE_RE.matches(t) && t.count { it.isDigit() } >= 3 && t.count { it.isLetter() } >= 1 && t.count { it.isDigit() } * 2 >= t.length) return ScanType.PHONE
        return ScanType.MESSAGE
    }

    fun analyze(input: String, model: UrlMlModel?, advanced: Boolean = false, blocklist: Set<String> = emptySet()): ManualScanOutcome =
        when (detectKind(input)) {
            ScanType.PHONE -> PhoneAnalyzer.analyze(input.trim())
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

    /** Which scam-wording categories a message hit, and why. */
    internal data class WordCheck(val categories: List<ScamCategory>, val reasons: List<ScanReason>)

    /** Plain-ASCII phrases are English: matched on whole words, ignoring case. Everything else (Chinese) is a substring match. */
    private fun isEnglish(p: String) = p.all { it.code < 128 }

    private val ENGLISH_MATCHERS: Map<String, Regex> by lazy {
        SCAM_CATEGORIES.flatMap { it.phrases }.filter(::isEnglish).associateWith { p ->
            val body = p.trim().split(Regex("\\s+")).joinToString("\\s+") { Regex.escape(it) }
            Regex("(?<![A-Za-z0-9])$body(?![A-Za-z0-9])", RegexOption.IGNORE_CASE)
        }
    }

    internal fun phraseMatches(text: String, phrase: String): Boolean =
        ENGLISH_MATCHERS[phrase]?.containsMatchIn(text) ?: text.contains(phrase, ignoreCase = true)

    internal fun checkScamWords(text: String): WordCheck {
        val reasons = mutableListOf<ScanReason>()
        val hitCategories = mutableListOf<ScamCategory>()
        for (c in SCAM_CATEGORIES) {
            val hits = c.phrases.filter { phraseMatches(text, it) }
            if (hits.isEmpty()) continue
            hitCategories += c
            val pts = c.weight.points + minOf(2, hits.size - 1) * EXTRA_PHRASE_POINTS
            reasons += ScanReason(c.rule, "${c.label} wording detected: ${hits.joinToString(", ")}", pts,
                when (c.weight) { Weight.HIGH -> "high"; Weight.MEDIUM -> "medium"; Weight.WEAK -> "low" })
        }
        return WordCheck(hitCategories, reasons)
    }

    private const val WORD_CAVEAT = "Word-based detection is a signal, not proof: a scam can be worded differently"

    private fun analyzeText(text: String, model: UrlMlModel?, advanced: Boolean, blocklist: Set<String>): ManualScanOutcome {
        val urls = extractUrls(text)
        val results = urls.map { evaluateUrl(it, model, advanced, blocklist) }
        val info = mutableListOf<String>()
        val reasons = mutableListOf<ScanReason>()

        // 1) Scam wording, grouped by category. Any one category is SUSPICIOUS at most.
        val words = checkScamWords(text)
        val cats = words.categories
        reasons += words.reasons
        var wordThreat = if (cats.isEmpty()) ThreatLevel.SAFE else ThreatLevel.WARNING

        // 2) Every URL goes through the existing URL pipeline (heuristics + ML); the worst one counts
        info += if (urls.isEmpty()) "No URLs found in the message" else "Found ${urls.size} URL(s) in the message"
        var urlThreat = ThreatLevel.SAFE
        for (r in results) {
            urlThreat = worse(urlThreat, r.threat)
            val h = shortHost(r.url)
            if (r.mlProbability != null) info += "ML: ${percent(r.mlProbability)}% phishing probability ($h)"
            for (x in r.reasons) if (x.rule != "no_issues") reasons += x.copy(detail = "($h) ${x.detail}")
        }

        // 3) DANGEROUS only when signals combine:
        //    (a) a bad link together with scam wording (a link rated DANGEROUS by itself is already DANGEROUS),
        //    (b) two or more HIGH-risk categories at the same time,
        //    (c) a credentials/OTP request together with urgency.
        val highCats = cats.filter { it.weight == Weight.HIGH }
        if (urlThreat != ThreatLevel.SAFE && cats.isNotEmpty()) {
            wordThreat = ThreatLevel.DANGER
            reasons += ScanReason("scam_words_with_link", "Scam wording combined with a suspicious link: very dangerous, do not click or share any details", 40, "high")
        }
        if (highCats.size >= 2) {
            wordThreat = ThreatLevel.DANGER
            reasons += ScanReason("scam_combined", "Several high-risk scam categories appear together (${highCats.joinToString(" + ") { it.label }}): very likely a scam", 40, "high")
        } else if (CREDENTIALS in cats && URGENCY in cats) {
            wordThreat = ThreatLevel.DANGER
            reasons += ScanReason("scam_credentials_urgent", "A request for credentials or codes combined with urgency: very likely a scam", 40, "high")
        }
        if (cats.isNotEmpty()) info += WORD_CAVEAT
        val threat = worse(wordThreat, urlThreat)
        if (reasons.isEmpty()) {
            reasons += ScanReason("no_issues", "No suspicious URLs or common scam wording found", 0, "low")
        }
        return ManualScanOutcome(ScanType.MESSAGE, threat, sorted(reasons), info, results)
    }
}
