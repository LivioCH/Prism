package com.example.prism.accessibility

import com.example.prism.ThreatLevel
import java.util.Locale

/** Result of the on-device (offline) URL analysis. */
data class LocalRiskReport(
    val url: String,
    val host: String?,
    val domain: String?,
    val score: Int,
    val level: ThreatLevel,
    val signals: List<RiskSignal>,
    val summary: String
)

/**
 * On-device heuristic phishing engine.
 *
 * In the merged app the primary scanner is the shared [com.example.prism.scan.ManualScanAnalyzer]
 * (rules + ML + Room cache). This engine is the last-resort fallback if the encrypted database or
 * the model asset cannot be opened, so screen monitoring keeps working instead of failing open.
 *
 * It looks for the traits that show up again and again in real-world smishing/phishing links:
 * brand impersonation, raw IP hosts, `@`-obfuscation, punycode homographs, disposable TLDs,
 * credential-harvesting wording, shortened links, payload downloads and open redirects.
 *
 * The result is advisory: a score of [DANGER_THRESHOLD] or more is what raises the full-screen
 * shield. False positives are recoverable through the allow-list.
 */
object UrlHeuristics {

    /** At or above this score the shield blocks the page. */
    const val DANGER_THRESHOLD = 68

    /** At or above this score the user gets a caution overlay. */
    const val WARNING_THRESHOLD = 30

    fun levelFor(score: Int): ThreatLevel = when {
        score >= DANGER_THRESHOLD -> ThreatLevel.DANGER
        score >= WARNING_THRESHOLD -> ThreatLevel.WARNING
        else -> ThreatLevel.SAFE
    }

    // ---------------------------------------------------------------------------------------
    // Reference data
    // ---------------------------------------------------------------------------------------

    private enum class MatchQuality(val weight: Int) { STRONG(70), MEDIUM(45), WEAK(20) }

    private data class BrandMatch(val brand: String, val official: String, val quality: MatchQuality)

    /** Brand token -> official registrable domain. Extend freely; order is not significant. */
    private val BRANDS: Map<String, String> = linkedMapOf(
        "paypal" to "paypal.com",
        "google" to "google.com",
        "gmail" to "gmail.com",
        "youtube" to "youtube.com",
        "apple" to "apple.com",
        "icloud" to "icloud.com",
        "microsoft" to "microsoft.com",
        "outlook" to "outlook.com",
        "amazon" to "amazon.com",
        "netflix" to "netflix.com",
        "facebook" to "facebook.com",
        "instagram" to "instagram.com",
        "whatsapp" to "whatsapp.com",
        "telegram" to "telegram.org",
        "discord" to "discord.com",
        "steam" to "steampowered.com",
        "roblox" to "roblox.com",
        "binance" to "binance.com",
        "coinbase" to "coinbase.com",
        "metamask" to "metamask.io",
        "shopee" to "shopee.tw",
        "lazada" to "lazada.com",
        "pchome" to "pchome.com.tw",
        "momo" to "momoshop.com.tw",
        "dhl" to "dhl.com",
        "fedex" to "fedex.com",
        "line" to "line.me",
        "wechat" to "wechat.com",
        "alipay" to "alipay.com",
        "taobao" to "taobao.com",
        "tiktok" to "tiktok.com",
        "linkedin" to "linkedin.com",
        "twitter" to "twitter.com",
        "github" to "github.com",
        "dropbox" to "dropbox.com",
        "adobe" to "adobe.com",
        "spotify" to "spotify.com",
        "uber" to "uber.com",
        "foodpanda" to "foodpanda.com",
        "esun" to "esunbank.com.tw",
        "cathay" to "cathaybk.com.tw",
        "ctbc" to "ctbcbank.com",
        "taishin" to "taishinbank.com.tw",
        "fubon" to "fubon.com",
        "megabank" to "megabank.com.tw",
        "landbank" to "landbank.com.tw",
        "firstbank" to "firstbank.com.tw",
        "sinopac" to "sinopac.com",
        "yuanta" to "yuanta.com",
        "scsb" to "scsb.com.tw",
        "hsbc" to "hsbc.com",
        "citibank" to "citibank.com",
        "dbs" to "dbs.com",
        "maybank" to "maybank2u.com"
    )

    /**
     * Domains that are trusted outright. Keep this list conservative: it is the "fast lane" that
     * skips scoring, so a mistake here means a phishing link would sail through.
     */
    private val BASE_TRUSTED_DOMAINS: Set<String> = setOf(
        "google.com", "gmail.com", "googleusercontent.com", "gstatic.com", "youtube.com",
        "youtube-nocookie.com", "android.com", "apple.com", "apple.news", "icloud.com",
        "microsoft.com", "microsoftonline.com", "office.com", "office.net", "live.com", "msn.com",
        "bing.com", "outlook.com", "windows.com", "amazon.com", "amazon.com.tw", "amazon.co.jp",
        "netflix.com", "facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com",
        "whatsapp.com", "whatsapp.net", "wa.me", "line.me", "line-apps.com", "naver.com",
        "telegram.org", "t.me", "discord.com", "discord.gg", "steampowered.com",
        "steamcommunity.com", "roblox.com", "twitter.com", "x.com", "linkedin.com", "github.com",
        "githubusercontent.com", "gitlab.com", "dropbox.com", "adobe.com", "spotify.com",
        "paypal.com", "stripe.com", "shopee.tw", "shopee.com.my", "lazada.com", "momoshop.com.tw",
        "pchome.com.tw", "books.com.tw", "rakuten.com.tw", "yahoo.com", "yahoo.com.tw", "pixnet.net",
        "104.com.tw", "591.com.tw", "uber.com", "ubereats.com", "foodpanda.com", "foodpanda.com.tw",
        "wikipedia.org", "wikimedia.org", "blogspot.com", "wordpress.com", "medium.com",
        "cloudflare.com", "twitch.tv", "imgur.com", "ntu.edu.tw", "nycu.edu.tw", "nctu.edu.tw",
        "gov.tw", "edu.tw", "org.tw", "dbs.com", "hsbc.com", "citibank.com", "maybank2u.com",
        // E.SUN serves the same site from both the .com and .com.tw properties.
        "esunbank.com", "esunbank.com.tw"
    )

    private val TRUSTED_DOMAINS: Set<String> = BASE_TRUSTED_DOMAINS + BRANDS.values

    private val SHORTENERS: Set<String> = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at",
        "ow.ly", "buff.ly", "rebrand.ly", "tiny.cc", "lnkd.in", "t.ly", "s.id", "v.gd",
        "shorte.st", "adf.ly", "clck.ru", "surl.li", "bit.do", "soo.gd", "u.to", "x.co", "zpr.io",
        "trib.al", "surl.li", "bl.ink"
    )

    private val HIGH_RISK_TLDS: Set<String> = setOf(
        "tk", "ml", "ga", "cf", "gq", "zip", "mov", "top", "xyz", "buzz", "click", "link",
        "work", "support", "rest", "icu", "cam", "sbs", "cfd", "cyou", "monster", "quest", "uno",
        "vip", "win", "bid", "loan", "date", "review", "racing", "accountant", "science", "party",
        "gdn", "faith", "stream", "download", "trade", "country", "men", "cricket", "webcam",
        "bar", "gives", "gifts", "deals", "sale", "shopping", "blackfriday", "christmas", "mom",
        "lol", "pics", "sexy", "bond", "beauty", "hair", "makeup", "skin", "autos", "boats",
        "yachts", "motorcycles", "homes", "wang", "ren", "kim"
    )

    private val CREDENTIAL_KEYWORDS: Set<String> = setOf(
        "login", "logon", "signin", "signon", "verify", "verification", "validate", "secure",
        "security", "account", "update", "confirm", "confirmation", "password", "passwd",
        "credential", "wallet", "billing", "payment", "invoice", "banking", "bank", "unlock",
        "recover", "recovery", "suspend", "suspended", "alert", "unusual", "otp", "2fa", "kyc",
        "authenticate", "authorize", "webscr"
    )

    private val LURE_KEYWORDS: Set<String> = setOf(
        "free", "gift", "gifts", "bonus", "prize", "winner", "claim", "reward", "airdrop",
        "usdt", "crypto", "bitcoin", "refund", "voucher", "coupon", "giveaway", "jackpot",
        "lottery", "nitro", "robux", "vbucks", "promo", "promotion", "discount", "cash"
    )

    /** Suffixes that turn a brand prefix into a lookalike (`paypalverify`, `esunbank`). */
    private val BRAND_GLUE_KEYWORDS: Set<String> = CREDENTIAL_KEYWORDS + LURE_KEYWORDS + setOf(
        "support", "service", "services", "help", "center", "centre", "official", "team", "id",
        "pay", "auth", "admin", "community", "group", "online", "shop", "store", "mobile", "app",
        "apps", "web", "portal", "mail", "sso", "tw", "com", "net", "org"
    )

    private val GENERIC_TOKENS: Set<String> = setOf(
        "www", "m", "web", "secure", "login", "signin", "account", "app", "api", "cdn", "static",
        "img", "mail", "sso", "id", "auth", "portal", "online", "my", "service", "services",
        "support", "help", "pay", "payment", "com", "net", "org", "tw", "hk", "cn", "jp", "sg"
    )

    private val EXECUTABLE_SUFFIXES = listOf(
        ".apk", ".exe", ".msi", ".scr", ".bat", ".cmd", ".vbs", ".jar", ".dmg", ".pkg", ".zip",
        ".rar", ".7z", ".iso", ".img", ".hta", ".ps1"
    )

    private val RANDOM_SEGMENT = Regex("""^[A-Za-z0-9_\-]{20,}$""")

    // ---------------------------------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------------------------------

    fun isTrustedHost(host: String): Boolean {
        val normalized = host.lowercase(Locale.ROOT).trimEnd('.')
        return TRUSTED_DOMAINS.any { domain ->
            normalized == domain || normalized.endsWith(".$domain")
        }
    }

    fun analyze(rawUrl: String): LocalRiskReport {
        val url = UrlTextParser.toAnalyzableUrl(rawUrl.trim())
        val parts = UrlTextParser.split(url)
        val host = UrlTextParser.hostOf(url)
        val domain = host?.let { UrlTextParser.registrableDomain(it) }

        if (host.isNullOrBlank()) {
            return LocalRiskReport(
                url = url,
                host = null,
                domain = null,
                score = 50,
                level = ThreatLevel.WARNING,
                signals = listOf(
                    RiskSignal(
                        label = "Unreadable destination",
                        weight = 50,
                        detail = "Prism could not work out where this link really goes."
                    )
                ),
                summary = "The destination of this link could not be resolved."
            )
        }

        val signals = mutableListOf<RiskSignal>()
        var score = 0

        fun flag(label: String, weight: Int, detail: String) {
            signals += RiskSignal(label, weight, detail)
            score += weight
        }

        val scheme = parts.scheme.lowercase(Locale.ROOT)
        val hasUserInfo = !UrlTextParser.userInfoOf(url).isNullOrBlank()
        val openRedirect = UrlTextParser.isOpenRedirect(parts.query)
        val isIpHost = UrlTextParser.isIpLiteral(host)

        // Fast lane: a recognised provider (and no redirect/@ trick to hijack it).
        if (isTrustedHost(host) && !openRedirect && !hasUserInfo) {
            val trustedScore = if (scheme == "https") 4 else 12
            return LocalRiskReport(
                url = url,
                host = host,
                domain = domain,
                score = trustedScore,
                level = levelFor(trustedScore),
                signals = emptyList(),
                summary = "This is the official ${domain ?: host} domain."
            )
        }

        if (scheme == "http") {
            flag(
                "Unencrypted connection",
                10,
                "The link uses plain http://, so anything typed on the page can be intercepted."
            )
        } else if (scheme == "ftp") {
            flag("File transfer link", 15, "The link opens a raw file transfer instead of a web page.")
        }

        if (isIpHost) {
            flag(
                "Raw IP address",
                55,
                "The link points straight at a numeric address (${host}) instead of a normal domain."
            )
        }

        if (hasUserInfo) {
            val disguise = UrlTextParser.userInfoOf(url).orEmpty()
            flag(
                "Disguised destination",
                55,
                "Everything before '@' in '$disguise' is decoration. The real site is $host."
            )
        }

        val hasPunycode = host.split('.').any { it.startsWith("xn--") }
        val hasNonAscii = host.any { it.code > 127 }
        when {
            hasPunycode -> flag(
                "Punycode lookalike",
                40,
                "The domain uses encoded international characters that can mimic a familiar brand."
            )

            hasNonAscii -> flag(
                "Mixed-script domain",
                25,
                "The domain contains non-Latin characters, a common way to fake familiar names."
            )
        }

        val tld = UrlTextParser.tldOf(host)
        if (tld in HIGH_RISK_TLDS) {
            flag(
                "High-risk domain ending",
                20,
                "The '.$tld' ending is cheap to register and heavily used by disposable phishing sites."
            )
        }

        if (SHORTENERS.any { host == it || host.endsWith(".$it") }) {
            flag(
                "Shortened link",
                30,
                "The real destination is hidden behind a link shortener, so it cannot be verified up front."
            )
        }

        val labels = host.split('.').filter { it.isNotEmpty() }
        val extraLabels = (labels.size - 2).coerceAtLeast(0)
        if (!isIpHost && extraLabels >= 2) {
            flag(
                "Deeply nested subdomain",
                12,
                "The address stacks $extraLabels extra subdomains in front of '$domain' to look official."
            )
        }

        // Count hyphens outside the punycode prefix, which legitimately contains two.
        val hyphenSource = labels.dropLast(1).joinToString(".").replace("xn--", "")
        val hyphens = hyphenSource.count { it == '-' }
        if (hyphens >= 3) {
            flag(
                "Excessive hyphens",
                12,
                "Domains packed with hyphens ('$host') are typical of throwaway phishing kits."
            )
        } else if (hyphens == 2) {
            flag(
                "Hyphenated domain",
                6,
                "Multiple hyphens in '$host' are often used to imitate an official name."
            )
        }

        val lowerUrl = url.lowercase(Locale.ROOT)
        val tokens = lowerUrl.split(Regex("[^a-z0-9]+")).filter { it.isNotEmpty() }.toSet()
        val credentialHits = CREDENTIAL_KEYWORDS.filter { it in tokens }
        if (credentialHits.isNotEmpty()) {
            val weight = minOf(credentialHits.size * 8, 28)
            flag(
                "Credential-harvesting wording",
                weight,
                "The address uses account-verification wording (${credentialHits.take(3).joinToString(", ")}), " +
                    "the same pattern used by fake login pages."
            )
        }

        val lureHits = LURE_KEYWORDS.filter { it in tokens }
        if (lureHits.isNotEmpty()) {
            flag(
                "Social-engineering lure",
                minOf(lureHits.size * 5, 10),
                "Wording such as ${lureHits.take(3).joinToString(", ")} is used to make the click feel rewarding."
            )
        }

        if (credentialHits.isNotEmpty() && lureHits.isNotEmpty()) {
            flag(
                "Lure plus login request",
                8,
                "A reward or alert is combined with an account request - a classic smishing combination."
            )
        }

        val brandMatch = matchBrand(host)
        if (brandMatch != null) {
            val weight = brandMatch.quality.weight
            when (brandMatch.quality) {
                MatchQuality.STRONG -> flag(
                    "Brand impersonation",
                    weight,
                    "This is not ${brandMatch.official}, yet the address is built around the " +
                        "${brandMatch.brand} brand."
                )

                MatchQuality.MEDIUM -> flag(
                    "Brand lookalike",
                    weight,
                    "The domain '$host' imitates ${brandMatch.brand}, whose real site is " +
                        "${brandMatch.official}."
                )

                MatchQuality.WEAK -> flag(
                    "Brand name reuse",
                    weight,
                    "The ${brandMatch.brand} name appears in an address that is not " +
                        "${brandMatch.official}."
                )
            }
        }

        if (brandMatch == null && credentialHits.isNotEmpty()) {
            val pathTokens = parts.path.lowercase(Locale.ROOT)
                .split(Regex("[^a-z0-9]+"))
                .filter { it.isNotEmpty() }
                .toSet()
            val pathBrand = BRANDS.keys.firstOrNull { it.length >= 5 && it in pathTokens }
            if (pathBrand != null) {
                flag(
                    "Brand name in URL path",
                    22,
                    "The address asks for account details on a page filed under '$pathBrand'."
                )
            }
        }

        if (brandMatch == null) {
            val leetTarget = deLeet(host)
            val spoofedBrand = BRANDS.keys.firstOrNull { brand ->
                brand.length >= 5 && leetTarget.contains(brand) && !host.contains(brand)
            }
            if (spoofedBrand != null && host.any { it.isDigit() }) {
                flag(
                    "Character-substitution spoof",
                    40,
                    "Digits inside '$host' stand in for letters, imitating $spoofedBrand."
                )
            }
        }

        val lowerPath = parts.path.lowercase(Locale.ROOT)
        if (EXECUTABLE_SUFFIXES.any { lowerPath.endsWith(it) }) {
            flag(
                "Payload download",
                25,
                "The link downloads an executable file rather than opening a normal web page."
            )
        }

        if (openRedirect) {
            flag(
                "Open redirect",
                30,
                "The address carries another URL in its parameters, so it can bounce you to an " +
                    "unrelated - possibly malicious - site."
            )
        }

        val suspiciousSegment = lowerPath.split('/').any { segment ->
            RANDOM_SEGMENT.matches(segment) &&
                segment.any { it.isDigit() } &&
                segment.any { it.isUpperCase() } &&
                segment.any { it.isLowerCase() }
        }
        if (suspiciousSegment) {
            flag(
                "Machine-generated path",
                8,
                "The path contains a long random-looking identifier, common in mass phishing kits."
            )
        }

        val port = UrlTextParser.portOf(url)
        if (port != null && port != 80 && port != 443) {
            flag(
                "Unusual network port",
                6,
                "The link connects on port $port instead of the normal web ports."
            )
        }

        if (parts.query.isNotBlank() && parts.query.count { it == '&' } + 1 >= 5) {
            flag(
                "Parameter-heavy link",
                4,
                "The link carries many parameters, a pattern often used to smuggle tracking or payload data."
            )
        }

        if (host.length > 40) {
            flag("Very long domain", 6, "The domain name is unusually long and hard to read.")
        }

        if (url.length > 200) {
            flag("Very long URL", 10, "The link is extremely long, which is often used to hide its real purpose.")
        } else if (url.length > 120) {
            flag("Long URL", 6, "The link is long enough to hide what it actually points at.")
        }

        val finalScore = score.coerceIn(0, 100)
        val summary = signals.maxByOrNull { it.weight }?.detail
            ?: "No known phishing patterns were found in this link."

        return LocalRiskReport(
            url = url,
            host = host,
            domain = domain,
            score = finalScore,
            level = levelFor(finalScore),
            signals = signals.sortedByDescending { it.weight },
            summary = summary
        )
    }

    // ---------------------------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------------------------

    private fun matchBrand(host: String): BrandMatch? {
        if (isTrustedHost(host)) return null

        val labels = host.split('.').filter { it.isNotEmpty() }
        val tld = labels.lastOrNull().orEmpty()
        val tokens = labels.flatMap { label -> label.split('-', '_') }.filter { it.isNotEmpty() }
        val significant = tokens.filter { it != tld }
        val domainMainLabel = UrlTextParser.registrableDomain(host).substringBefore('.')
        val domainTokens = domainMainLabel.split('-', '_').filter { it.isNotEmpty() }.toSet()

        // 1) Exact brand label somewhere in the host.
        for ((brand, official) in BRANDS) {
            if (brand.length < 3 || brand !in tokens) continue
            val brandOwnsRegistrableDomain = brand in domainTokens
            val othersGlue = significant
                .filter { it != brand }
                .all { it in BRAND_GLUE_KEYWORDS || it in GENERIC_TOKENS }
            val quality = when {
                !brandOwnsRegistrableDomain -> MatchQuality.STRONG
                othersGlue -> MatchQuality.STRONG
                else -> MatchQuality.WEAK
            }
            return BrandMatch(brand, official, quality)
        }

        // 2) Brand glued to a keyword in one label: paypalverify, esunbank, discordgift.
        for ((brand, official) in BRANDS) {
            if (brand.length < 4) continue
            val hit = tokens.firstOrNull { token ->
                token.length > brand.length &&
                    token.startsWith(brand) &&
                    token.substring(brand.length) in BRAND_GLUE_KEYWORDS
            }
            if (hit != null) return BrandMatch(brand, official, MatchQuality.MEDIUM)
        }

        // 3) Brand buried somewhere in a longer label.
        val compact = host.replace("-", "").replace("_", "")
        for ((brand, official) in BRANDS) {
            if (brand.length < 5) continue
            if (compact.contains(brand)) return BrandMatch(brand, official, MatchQuality.WEAK)
        }
        return null
    }

    private fun deLeet(value: String): String = buildString {
        for (character in value.lowercase(Locale.ROOT)) {
            append(
                when (character) {
                    '0' -> 'o'
                    '1' -> 'l'
                    '3' -> 'e'
                    '4' -> 'a'
                    '5' -> 's'
                    '7' -> 't'
                    '8' -> 'b'
                    '@' -> 'a'
                    else -> character
                }
            )
        }
    }
}
