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
 *  - phone number   -> Taiwan-focused heuristic rules ONLY (there is no ML dataset for phone numbers)
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

    /** One group of Traditional-Chinese scam wording. [strong] categories weigh more than weak ones. */
    internal data class ScamCategory(val rule: String, val label: String, val strong: Boolean, val phrases: List<String>)

    internal val SCAM_CATEGORIES = listOf(
        ScamCategory("scam_urgency", "急迫性", false, listOf("立即", "馬上", "盡快", "24小時", "逾期", "緊急", "最後通知")),
        ScamCategory("scam_account_threat", "帳號威脅", true, listOf("帳號異常", "帳號將被凍結", "帳號停用", "身分驗證", "重新驗證")),
        ScamCategory("scam_prize_bait", "中獎誘餌", true, listOf("中獎", "得獎", "免費領取", "紅包", "抽中")),
        ScamCategory("scam_money", "金錢", true, listOf("退款", "退稅", "匯款", "轉帳", "補繳", "手續費", "解除分期付款")),
        ScamCategory("scam_credentials", "憑證/連結", true, listOf("點擊連結", "請登入", "驗證碼", "輸入密碼", "輸入OTP", "信用卡")),
        ScamCategory("scam_parcel", "包裹物流", false, listOf("包裹", "無法配送", "地址有誤", "重新配送", "補件"))
    )
    private const val STRONG_POINTS = 20       // first phrase of a strong category
    private const val WEAK_POINTS = 10         // first phrase of a weak category
    private const val EXTRA_PHRASE_POINTS = 5  // each further phrase of the same category (max 2)
    private const val WARNING_AT = 20
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

    /** Result of the scam-wording check for one message. */
    internal data class WordCheck(val points: Int, val categories: List<ScamCategory>, val reasons: List<ScanReason>)

    internal fun checkScamWords(text: String): WordCheck {
        val reasons = mutableListOf<ScanReason>()
        val hitCategories = mutableListOf<ScamCategory>()
        var total = 0
        for (c in SCAM_CATEGORIES) {
            val hits = c.phrases.filter { text.contains(it, ignoreCase = true) }
            if (hits.isEmpty()) continue
            hitCategories += c
            val pts = (if (c.strong) STRONG_POINTS else WEAK_POINTS) + minOf(2, hits.size - 1) * EXTRA_PHRASE_POINTS
            total += pts
            reasons += ScanReason(c.rule, "偵測到${c.label}用語：${hits.joinToString("、")}", pts,
                if (pts >= 30) "high" else if (pts >= 15) "medium" else "low")
        }
        // Several different categories together are far more typical for a scam than one category alone
        total += when (hitCategories.size) { 0, 1 -> 0; 2 -> 8; else -> 15 }
        return WordCheck(minOf(100, total), hitCategories, reasons)
    }

    private fun analyzeText(text: String, model: UrlMlModel?, advanced: Boolean, blocklist: Set<String>): ManualScanOutcome {
        val urls = extractUrls(text)
        val results = urls.map { evaluateUrl(it, model, advanced, blocklist) }
        val info = mutableListOf<String>()
        val reasons = mutableListOf<ScanReason>()

        // 1) Scam wording, grouped by category
        val words = checkScamWords(text)
        reasons += words.reasons
        var wordThreat = when {
            words.points >= DANGER_AT -> ThreatLevel.DANGER
            words.points >= WARNING_AT -> ThreatLevel.WARNING
            else -> ThreatLevel.SAFE
        }

        // 2) Every URL goes through the existing URL pipeline (heuristics + ML); the worst one counts
        info += if (urls.isEmpty()) "訊息中未發現網址" else "訊息中找到 ${urls.size} 個網址"
        var urlThreat = ThreatLevel.SAFE
        for (r in results) {
            urlThreat = worse(urlThreat, r.threat)
            val h = shortHost(r.url)
            if (r.mlProbability != null) info += "ML: ${percent(r.mlProbability)}% phishing probability ($h)"
            for (x in r.reasons) if (x.rule != "no_issues") reasons += x.copy(detail = "($h) ${x.detail}")
        }

        // 3) Combine. DANGEROUS from a bad link needs several signals together: wording from at least
        //    two categories (one of them strong, e.g. account threat / money / credentials).
        val strongCats = words.categories.count { it.strong }
        if (urlThreat != ThreatLevel.SAFE && words.categories.size >= 2 && strongCats >= 1) {
            wordThreat = ThreatLevel.DANGER
            reasons += ScanReason("scam_words_with_link", "詐騙用語結合可疑連結，風險極高，請勿點擊或提供資料", 40, "high")
        }
        val threat = worse(wordThreat, urlThreat)
        if (reasons.isEmpty()) {
            reasons += ScanReason("no_issues", "未發現可疑網址或常見詐騙用語", 0, "low")
        }
        return ManualScanOutcome(ScanType.MESSAGE, threat, sorted(reasons), info, results)
    }

    // ---------------------------------------------------------------- phone (Taiwan heuristics)

    private val TW_MOBILE = Regex("^09\\d{8}$")
    // Valid Taiwan area codes, longest first so "0826" wins over "082" and "08"
    private val TW_AREA_CODES = listOf("0826", "0836", "037", "049", "089", "082", "02", "03", "04", "05", "06", "07", "08")
    private const val PHONE_NOTE = "此為啟發式判斷，非官方資料庫"

    /** Domestic Taiwan format: mobile 09 + 8 digits, or a valid area code with 9-10 digits in total. */
    internal fun isTaiwanFormat(domestic: String): Boolean {
        if (TW_MOBILE.matches(domestic)) return true
        if (domestic.length !in 9..10 || !domestic.all { it.isDigit() }) return false
        return TW_AREA_CODES.any { domestic.startsWith(it) && domestic.length - it.length >= 5 }
    }

    // Calling codes often used in "one ring" / callback scams
    private val RISKY_CODES = setOf("225", "232", "234", "236", "242", "243", "252", "257", "375", "592", "809", "876")

    private fun analyzePhone(raw: String): ManualScanOutcome {
        val reasons = mutableListOf<ScanReason>()
        fun add(rule: String, pts: Int, detail: String) {
            reasons += ScanReason(rule, detail, pts, if (pts >= 35) "high" else if (pts >= 15) "medium" else "low")
        }
        // Normalise: drop spaces, hyphens and brackets
        val compact = raw.filterNot { it.isWhitespace() || it == '-' || it == '(' || it == ')' }
        var international = compact.startsWith("+")
        var digits = compact.filter { it.isDigit() }
        if (!international && digits.startsWith("00")) { international = true; digits = digits.drop(2) }

        if (compact.drop(1).any { !it.isDigit() }) add("odd_chars", 10, "號碼含有異常字元")
        if (digits.length < 8) add("too_short", 25, "號碼長度異常：只有 ${digits.length} 位數字（太短）")
        if (digits.length > 15) add("too_long", 25, "號碼長度異常：共 ${digits.length} 位數字，超過國際標準上限")

        var validTaiwan = false
        if (international) {
            if (digits.startsWith("886")) {
                val rest = digits.drop(3)
                val asDomestic = if (rest.startsWith("0")) rest else "0$rest"
                if (isTaiwanFormat(asDomestic)) {
                    add("fake_local_intl", 40, "國際冒充本地號碼 (+886)：這是台灣本地格式的號碼卻以國際號碼顯示，是常見的詐騙手法")
                } else {
                    add("odd_tw_intl", 20, "+886 後面的號碼不符合台灣號碼格式")
                }
                if (rest.startsWith("0")) add("leading_zero", 10, "+886 後多出一個 0，格式不正確")
            } else if (digits.length >= 4) {
                val code = (3 downTo 1).map { digits.take(it) }.firstOrNull { it in RISKY_CODES }
                add("foreign_number", 20, "來自非預期的國際號碼 (+${code ?: digits.take(3)})")
                if (code != null) add("risky_country", 10, "國碼 +$code 常見於「響一聲」回撥詐騙")
            }
        } else if (isTaiwanFormat(digits)) {
            validTaiwan = true
            add("no_issues", 0, "符合台灣手機或市話號碼格式")
        } else if (digits.length in 8..15) {
            add("not_tw_format", 10, "不符合台灣常見的手機或市話號碼格式")
        }

        // Pattern checks are skipped for numbers that already match a valid Taiwan format
        if (!validTaiwan && digits.isNotEmpty()) {
            val asc = "0123456789"
            val allSame = digits.length >= 4 && digits.all { it == digits[0] }
            val repeated = Regex("(\\d)\\1{5,}").containsMatchIn(digits)
            val sequential = digits.length >= 6 && (0..digits.length - 6).any { i -> digits.substring(i, i + 6).let { it in asc || it.reversed() in asc } }
            if (allSame || repeated || sequential) add("odd_pattern", 10, "號碼格式異常：含有重複或連續的數字")
        }
        if (reasons.isEmpty()) add("no_issues", 0, "未發現明顯可疑特徵")

        val score = minOf(100, reasons.sumOf { it.points })
        val threat = when {
            score >= 60 -> ThreatLevel.DANGER
            score >= 25 -> ThreatLevel.WARNING
            else -> ThreatLevel.SAFE
        }
        return ManualScanOutcome(ScanType.PHONE, threat, sorted(reasons), listOf(PHONE_NOTE))
    }
}
