package com.example.prism.scan

import kotlin.math.ln

/**
 * Turns a URL into the 15 numbers the model was trained on. Only the HOST NAME is looked at, never the
 * path or query: in the training data almost every legitimate URL is a bare homepage, so a model that
 * sees the path learns "path = phishing" and flags real login pages (https://school.edu/login/index.php).
 *
 * The ORDER and the formulas must stay identical to the training script (ml/train_url_model.js, function
 * `features`). ml/parity_vectors.json holds the script's answers for sample URLs and a unit test compares them.
 */
object FeatureExtractor {
    val FEATURE_NAMES = listOf(
        "host_length", "has_ip", "num_subdomains", "sus_tld", "host_hyphens", "host_digits", "host_entropy",
        "longest_label", "free_host", "brand_in_host", "longest_digit_run", "sld_length", "tld_phish_rate", "host_dots",
        "institution"
    )

    /** Lists that ship inside url_model.json, so the app and the training script share one copy. */
    class Vocab(
        val susTld: Set<String>,
        val freeHosts: List<String>,        // free hosting / site builders that phishing pages often sit on
        val brands: List<String>,           // brand names that scam sites like to put in their address
        val secondLevel: Set<String>,       // "co", "com", "ac" ...: co.uk-style endings
        val institution: Set<String>,       // "edu", "gov", "ac" ...: schools and governments (school.edu, uni.ac.jp)
        val tldPrior: Double,               // how often a URL is phishing overall (for endings not seen in training)
        val tldRate: Map<String, Double>    // how often each ending was phishing in the training data
    )

    private val SCHEME = Regex("^https?://", RegexOption.IGNORE_CASE)
    private val WWW = Regex("^www\\.", RegexOption.IGNORE_CASE)
    private val IPV4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private val DIGITS = Regex("\\d+")

    fun extract(url: String, v: Vocab): DoubleArray {
        val noScheme = url.replace(SCHEME, "")
        // A leading "www." is dropped: in the training data nearly every legitimate URL has it, so keeping it
        // teaches the model "no www = phishing" (and flags github.com).
        val hostFull = noScheme.substringBefore('/').substringBefore('?').replace(WWW, "")
        val host = hostFull.substringBefore(':').lowercase()
        val labels = host.split('.')
        val tld = labels.last()
        val regN = if (labels.size >= 3 && labels[labels.size - 2] in v.secondLevel && tld.length == 2) 3 else 2
        val sld = if (labels.size >= regN) labels[labels.size - regN] else labels[0]

        return doubleArrayOf(
            hostFull.length.toDouble(),                                              // 0 host_length
            if (IPV4.matches(hostFull)) 1.0 else 0.0,                                // 1 has_ip
            maxOf(0, labels.size - 2).toDouble(),                                    // 2 num_subdomains
            if (tld in v.susTld) 1.0 else 0.0,                                       // 3 sus_tld
            host.count { it == '-' }.toDouble(),                                     // 4 host_hyphens
            host.count { it in '0'..'9' }.toDouble(),                                // 5 host_digits
            entropy(host),                                                           // 6 host_entropy
            labels.maxOf { it.length }.toDouble(),                                   // 7 longest_label
            if (v.freeHosts.any { host == it || host.endsWith(".$it") }) 1.0 else 0.0, // 8 free_host
            if (v.brands.any { host.contains(it) && sld != it }) 1.0 else 0.0,       // 9 brand_in_host
            (DIGITS.findAll(host).maxOfOrNull { it.value.length } ?: 0).toDouble(),  // 10 longest_digit_run
            sld.length.toDouble(),                                                   // 11 sld_length
            v.tldRate[tld] ?: v.tldPrior,                                            // 12 tld_phish_rate
            (labels.size - 1).toDouble(),                                            // 13 host_dots
            if (tld in v.institution || (labels.size >= 2 && labels[labels.size - 2] in v.institution)) 1.0 else 0.0 // 14 institution
        )
    }

    /** Shannon entropy (bits per character) of the host name. */
    internal fun entropy(s: String): Double {
        if (s.isEmpty()) return 0.0
        var h = 0.0
        for ((_, n) in s.groupingBy { it }.eachCount()) {
            val p = n.toDouble() / s.length
            h -= p * (ln(p) / ln(2.0))
        }
        return h
    }
}
