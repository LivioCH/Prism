package com.example.prism.accessibility

import java.text.Normalizer
import java.util.Locale

/**
 * Pure-Kotlin URL discovery and parsing for on-screen text.
 *
 * This file deliberately has **no Android imports** so the detection rules can be exercised by
 * fast JVM unit tests (`UrlTextParserTest`). [UrlExtractor] is the Android counterpart that walks
 * the accessibility node tree and feeds raw screen text into this parser.
 *
 * Design notes
 * ------------
 *  * Only ASCII printable characters are accepted inside a URL. Chat apps append CJK text
 *    directly after a link with no whitespace (`點擊https://x.com領取`), and a permissive `\S+`
 *    pattern would swallow the whole sentence.
 *  * Text is normalised before matching so common evasions (`evil[.]com`, `hxxp://`,
 *    zero-width characters, full-width dots) are still caught.
 *  * Bare domains (`secure-bank-login.com`) are recognised because messaging apps frequently
 *    render links without the scheme.
 *  * Parsing is manual instead of `java.net.URI` because chat text contains malformed URLs that
 *    make `URI` throw, and we still want to reason about those.
 */
object UrlTextParser {

    private const val MAX_TEXT_LENGTH = 20_000
    private const val MAX_URL_LENGTH = 2_048
    private const val DEFAULT_LIMIT = 8

    /** ASCII characters allowed inside a URL (RFC 3986 subset, minus quotes/brackets). */
    private const val URL_CHARS = """[A-Za-z0-9\-._~:/?#@!&*+,;=%]"""

    /**
     * Two-label public suffixes, e.g. `com.tw`. Ordered longest-first when the final pattern is
     * built so a greedy match never stops at `com` and leaves `.tw` behind.
     */
    private val MULTI_PART_SUFFIXES = listOf(
        "com.tw", "org.tw", "net.tw", "edu.tw", "gov.tw", "idv.tw",
        "com.hk", "org.hk", "edu.hk", "net.hk",
        "com.cn", "net.cn", "org.cn", "gov.cn",
        "com.sg", "com.my", "co.id", "or.id",
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
        "co.jp", "ne.jp", "or.jp",
        "co.kr", "or.kr",
        "com.au", "net.au", "org.au",
        "com.br", "com.mx", "com.ar", "com.tr", "com.vn", "com.ph",
        "co.th", "co.in", "co.za", "co.nz", "com.ua", "com.pl", "com.es", "com.ru"
    )

    /**
     * Single-label suffixes that are safe to detect without a scheme. Ambiguous file-extension
     * style ccTLDs (`.md`, `.sh`, `.so`, `.to`, `.pl`, `.zip`, `.mov`, ...) are intentionally
     * excluded so a chat message about `readme.md` is not reported as a link.
     */
    private val SINGLE_TLDS = setOf(
        // generic
        "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name", "pro", "mobi",
        "asia", "tel", "travel", "jobs", "cat", "museum", "aero", "coop",
        "io", "co", "ai", "app", "dev", "tech", "online", "site", "website", "store", "shop",
        "space", "xyz", "top", "club", "link", "click", "live", "life", "world", "today", "news",
        "media", "agency", "digital", "solutions", "services", "support", "help", "center",
        "company", "group", "global", "network", "systems", "software", "cloud", "host", "page",
        "email", "blog", "wiki", "design", "studio", "photo", "pics", "video", "music", "radio",
        "stream", "download", "games", "fun", "art", "ink", "zone", "city", "country", "estate",
        "finance", "financial", "capital", "money", "bank", "credit", "loan", "insurance", "law",
        "legal", "attorney", "doctor", "health", "care", "clinic", "hospital", "pharmacy",
        "fitness", "coffee", "pizza", "recipes", "garden", "homes", "land", "farm", "tools",
        "build", "construction", "repair", "cleaning", "glass", "lighting", "paint", "roofing",
        "academy", "school", "university", "college", "education", "training", "courses",
        "degree", "mba", "expert", "guru", "consulting", "management", "marketing", "plus",
        "vip", "icu", "buzz", "monster", "quest", "sbs", "cfd", "cyou", "uno", "bond", "rest",
        "bar", "cam", "men", "bid", "win", "trade", "review", "date", "racing", "accountant",
        "science", "party", "gdn", "faith", "rocks", "wang", "ren", "kim", "mom", "lol",
        "makeup", "beauty", "hair", "skin", "autos", "boats", "yachts", "motorcycles", "gifts",
        "gives", "deals", "sale", "shopping", "blackfriday", "christmas", "halloween", "discount",
        // country codes that read clearly as domains
        "tw", "hk", "cn", "jp", "kr", "sg", "my", "id", "th", "vn", "ph", "uk", "us", "de",
        "fr", "es", "it", "nl", "ru", "br", "in", "au", "ca", "ch", "se", "no", "dk", "fi",
        "ie", "il", "at", "be", "cz", "gr", "hu", "nz", "ro", "sk", "tr", "ua", "za", "mx",
        "ar", "cl", "pt", "ae", "sa", "tv", "me",
        // High-abuse endings that are not also common file extensions. Browsers hide the scheme,
        // so a scheme-less `brand-verify.tk` must still be recognised.
        "tk", "ml", "ga", "cf", "gq", "cricket", "webcam", "sexy"
    )

    /** Longest alternative first is required: `com` must win over `co`. */
    private val TLD_PATTERN: String = (MULTI_PART_SUFFIXES + SINGLE_TLDS)
        .distinct()
        .sortedByDescending { it.length }
        .joinToString("|") { Regex.escape(it) }

    private val SCHEME_URL_REGEX = Regex("""(?i)(?<![\w@])(?:https?|ftp)://$URL_CHARS+""")

    private val WWW_URL_REGEX = Regex("""(?i)(?<![\w@.\-])www\.$URL_CHARS+""")

    private val BARE_DOMAIN_REGEX = Regex(
        """(?i)(?<![\w@.\-])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+""" +
            """(?:$TLD_PATTERN)(?::\d{1,5})?(?:[/?]$URL_CHARS*)?"""
    )

    private val IPV4_REGEX = Regex("""\d{1,3}(?:\.\d{1,3}){3}""")

    private val ZERO_WIDTH = Regex("""[\u200B-\u200D\uFEFF\u00AD\u2060]""")

    private val FULL_WIDTH_DOTS = Regex("[。．｡]")

    private val DEOBFUSCATE_SCHEME = Regex("""(?i)hxxp(s?)://""")

    private val DEOBFUSCATE_DOT = Regex(
        """(?i)\s*(?:\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\})\s*"""
    )

    private val DEOBFUSCATE_DOT_WORD = Regex("""(?i)(?<=[a-z0-9])\s+dot\s+(?=[a-z0-9])""")

    private const val TRAILING_PUNCTUATION = ".,;:!?'\")]}>*"

    /** Characters before which a new URL must not start (avoids matching inside emails). */
    private val REDIRECT_PARAM_KEYS = setOf(
        "url", "uri", "redirect", "redirect_url", "redirect_uri", "next", "target", "dest",
        "destination", "continue", "return", "returnurl", "goto", "r", "u", "link", "out"
    )

    // ---------------------------------------------------------------------------------------
    // Discovery
    // ---------------------------------------------------------------------------------------

    /**
     * Extracts every plausible URL from a block of screen text, de-duplicated case-insensitively
     * while preserving the original casing for display.
     */
    fun findUrls(text: String, limit: Int = DEFAULT_LIMIT): List<String> {
        if (text.isBlank()) return emptyList()
        val normalized = normalize(text)
        val occupied = BooleanArray(normalized.length)
        val found = LinkedHashMap<String, String>()

        for (regex in listOf(SCHEME_URL_REGEX, WWW_URL_REGEX, BARE_DOMAIN_REGEX)) {
            if (found.size >= limit) break
            for (match in regex.findAll(normalized)) {
                if (match.value.isEmpty()) continue
                if (overlaps(occupied, match.range)) continue
                val candidate = trimTrailing(match.value)
                if (!looksLikeUrl(candidate)) continue

                val key = candidate.lowercase(Locale.ROOT).trimEnd('/')
                if (key.length < 4) continue
                if (!found.containsKey(key)) found[key] = candidate
                markOccupied(occupied, match.range)
                if (found.size >= limit) break
            }
        }
        return found.values.toList()
    }

    /** True when [value] has a resolvable host and could reasonably be a web link. */
    fun looksLikeUrl(value: String): Boolean {
        if (value.length !in 4..MAX_URL_LENGTH) return false
        if (value.contains("..")) return false
        val host = hostOf(value) ?: return false
        if (host.isEmpty() || host.length > 253) return false
        if (host.startsWith(".") || host.endsWith(".") || host.startsWith("-") || host.endsWith("-")) {
            return false
        }
        if (isIpLiteral(host)) return true
        if (!host.contains('.')) return false
        val labels = host.split('.')
        if (labels.any { it.isEmpty() || it.length > 63 }) return false
        val tld = labels.last()
        if (tld.length < 2 || tld.all { it.isDigit() }) return false
        return true
    }

    private fun overlaps(occupied: BooleanArray, range: IntRange): Boolean {
        for (index in range) {
            if (index in occupied.indices && occupied[index]) return true
        }
        return false
    }

    private fun markOccupied(occupied: BooleanArray, range: IntRange) {
        for (index in range) {
            if (index in occupied.indices) occupied[index] = true
        }
    }

    private fun trimTrailing(value: String): String {
        var end = value.length
        while (end > 0 && value[end - 1] in TRAILING_PUNCTUATION) end--
        return if (end == value.length) value else value.substring(0, end)
    }

    // ---------------------------------------------------------------------------------------
    // Normalisation
    // ---------------------------------------------------------------------------------------

    /**
     * Unicode-normalises the text and reverses the most common "link breaking" tricks so the
     * detector sees what the reader actually sees.
     */
    fun normalize(text: String): String {
        if (text.isEmpty()) return text
        val clipped = if (text.length > MAX_TEXT_LENGTH) text.substring(0, MAX_TEXT_LENGTH) else text
        var value = Normalizer.normalize(clipped, Normalizer.Form.NFKC)
        value = ZERO_WIDTH.replace(value, "")
        value = FULL_WIDTH_DOTS.replace(value, ".")
        value = DEOBFUSCATE_SCHEME.replace(value) { match ->
            if (match.groupValues[1].isEmpty()) "http://" else "https://"
        }
        value = DEOBFUSCATE_DOT.replace(value, ".")
        value = DEOBFUSCATE_DOT_WORD.replace(value, ".")
        return value
    }

    // ---------------------------------------------------------------------------------------
    // Parsing
    // ---------------------------------------------------------------------------------------

    /** Structural pieces of a URL. Missing pieces are empty strings, never null. */
    data class UrlParts(
        val scheme: String,
        val authority: String,
        val path: String,
        val query: String,
        val fragment: String
    )

    fun split(rawUrl: String): UrlParts {
        var remainder = toAnalyzableUrl(rawUrl).trim()
        var scheme = ""
        val schemeSeparator = remainder.indexOf("://")
        if (schemeSeparator > 0) {
            scheme = remainder.substring(0, schemeSeparator).lowercase(Locale.ROOT)
            remainder = remainder.substring(schemeSeparator + 3)
        }

        var fragment = ""
        val hashIndex = remainder.indexOf('#')
        if (hashIndex >= 0) {
            fragment = remainder.substring(hashIndex + 1)
            remainder = remainder.substring(0, hashIndex)
        }

        var query = ""
        val questionIndex = remainder.indexOf('?')
        if (questionIndex >= 0) {
            query = remainder.substring(questionIndex + 1)
            remainder = remainder.substring(0, questionIndex)
        }

        val slashIndex = remainder.indexOf('/')
        val authority = if (slashIndex >= 0) remainder.substring(0, slashIndex) else remainder
        val path = if (slashIndex >= 0) remainder.substring(slashIndex) else ""

        return UrlParts(scheme, authority, path, query, fragment)
    }

    /** Adds `https://` when the scheme is missing so the value can be parsed uniformly. */
    fun toAnalyzableUrl(rawUrl: String): String {
        val value = rawUrl.trim()
        if (value.isEmpty()) return value
        return if (value.contains("://")) value else "https://$value"
    }

    /** Host only, lower-cased, without user info, port, IPv6 brackets or trailing dot. */
    fun hostOf(rawUrl: String): String? {
        var authority = split(rawUrl).authority
        if (authority.isEmpty()) return null

        val atIndex = authority.lastIndexOf('@')
        if (atIndex >= 0) authority = authority.substring(atIndex + 1)

        if (authority.startsWith("[")) {
            val closing = authority.indexOf(']')
            if (closing > 0) {
                return authority.substring(1, closing).lowercase(Locale.ROOT)
                    .takeIf { it.isNotEmpty() }
            }
        }

        val colon = authority.lastIndexOf(':')
        if (colon > 0 && authority.indexOf(':') == colon) authority = authority.substring(0, colon)

        authority = authority.trimEnd('.')
        return authority.lowercase(Locale.ROOT).takeIf { it.isNotEmpty() }
    }

    /** Returns the user-info part (`paypal.com` in `https://paypal.com@evil.tk`), if present. */
    fun userInfoOf(rawUrl: String): String? {
        val authority = split(rawUrl).authority
        val atIndex = authority.lastIndexOf('@')
        if (atIndex <= 0) return null
        return authority.substring(0, atIndex).takeIf { it.isNotEmpty() }
    }

    fun portOf(rawUrl: String): Int? {
        val authority = split(rawUrl).authority
        if (authority.contains('@')) return null
        val colon = authority.lastIndexOf(':')
        if (colon <= 0 || authority.indexOf(':') != colon) return null
        return authority.substring(colon + 1).toIntOrNull()
    }

    fun tldOf(host: String): String =
        host.substringAfterLast('.', "").lowercase(Locale.ROOT)

    /**
     * Best-effort registrable domain (`a.b.example.com.tw` -> `example.com.tw`), good enough for
     * allow-listing without shipping a full public-suffix list.
     */
    fun registrableDomain(host: String): String {
        val labels = host.trimEnd('.').split('.').filter { it.isNotEmpty() }
        if (labels.size <= 2) return labels.joinToString(".")

        val last = labels.last()
        val secondLast = labels[labels.size - 2]
        val suffixLabels = if (last.length == 2 && secondLast in SECOND_LEVEL_SUFFIX_LABELS) 2 else 1

        if (labels.size <= suffixLabels) return labels.joinToString(".")
        return labels.takeLast(suffixLabels + 1).joinToString(".")
    }

    /** Stable cache/dedupe key. Case-insensitive, trailing slashes removed. */
    fun cacheKey(rawUrl: String): String =
        toAnalyzableUrl(rawUrl).trim().trimEnd('/').lowercase(Locale.ROOT)

    fun isIpLiteral(host: String): Boolean =
        IPV4_REGEX.matches(host) || host.contains(':')

    fun isOpenRedirect(query: String): Boolean {
        if (query.isBlank()) return false
        return query.split('&').any { parameter ->
            val key = parameter.substringBefore('=').lowercase(Locale.ROOT)
            if (key !in REDIRECT_PARAM_KEYS) return@any false
            val value = decode(parameter.substringAfter('=', ""))
            value.contains("://") || value.startsWith("//") ||
                (value.contains('.') && hostOf(value)?.contains('.') == true)
        }
    }

    private fun decode(value: String): String =
        try {
            java.net.URLDecoder.decode(value, "UTF-8")
        } catch (_: Exception) {
            value
        }

    private val SECOND_LEVEL_SUFFIX_LABELS = setOf(
        "com", "net", "org", "edu", "gov", "mil", "co", "ac", "or", "ne", "go", "gob", "idv",
        "nom", "web", "biz", "info", "sch", "id"
    )
}
