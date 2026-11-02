package com.example.prism.scan

/**
 * Turns a URL into the 14 numbers the model was trained on. The ORDER and the formulas must stay
 * identical to the Python training code (see "features" in assets/url_model.json).
 */
object FeatureExtractor {
    val FEATURE_NAMES = listOf(
        "url_length", "host_length", "num_dots", "num_hyphens", "num_digits", "num_special", "num_slashes",
        "has_ip", "has_at", "num_subdomains", "sus_tld", "has_keyword", "digit_ratio", "double_slash"
    )

    private val SCHEME = Regex("^https?://", RegexOption.IGNORE_CASE)
    private val IPV4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private const val SPECIAL = "@%=&?_~"

    fun extract(url: String, susTld: Set<String>, keywords: List<String>): DoubleArray {
        val urlLength = url.length
        val noScheme = url.replace(SCHEME, "")                    // drop http:// or https://
        val host = noScheme.substringBefore('/').substringBefore('?') // before first '/', query removed
        val numDigits = url.count { it in '0'..'9' }
        val labels = host.split('.')
        val tld = labels.last().lowercase()
        val lower = url.lowercase()
        val digitRatio = if (urlLength == 0) 0.0 else Math.round(numDigits.toDouble() / urlLength * 10000.0) / 10000.0

        return doubleArrayOf(
            urlLength.toDouble(),                                            // 0 url_length
            host.length.toDouble(),                                          // 1 host_length
            url.count { it == '.' }.toDouble(),                              // 2 num_dots
            url.count { it == '-' }.toDouble(),                              // 3 num_hyphens
            numDigits.toDouble(),                                            // 4 num_digits
            url.count { it in SPECIAL }.toDouble(),                          // 5 num_special
            url.count { it == '/' }.toDouble(),                              // 6 num_slashes
            if (IPV4.matches(host)) 1.0 else 0.0,                            // 7 has_ip
            if (url.contains('@')) 1.0 else 0.0,                             // 8 has_at
            maxOf(0, labels.size - 2).toDouble(),                            // 9 num_subdomains
            if (tld in susTld) 1.0 else 0.0,                                 // 10 sus_tld
            if (keywords.any { lower.contains(it) }) 1.0 else 0.0,           // 11 has_keyword
            digitRatio,                                                      // 12 digit_ratio
            if (noScheme.contains("//")) 1.0 else 0.0                        // 13 double_slash
        )
    }
}
