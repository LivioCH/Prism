package com.example.prism.scan

import kotlin.math.exp

/**
 * Logistic-regression URL model, plain arithmetic only (no ML library, no network).
 * Weights live in assets/url_model.json and come from ml/train_url_model.js (trained on the PhiUSIIL dataset).
 * Parsing is a tiny regex reader on purpose, so the same code runs in unit tests (no Android org.json needed).
 */
class UrlMlModel(
    val features: List<String>,
    private val mean: DoubleArray,
    private val scale: DoubleArray,
    private val coef: DoubleArray,
    private val intercept: Double,
    private val vocab: FeatureExtractor.Vocab
) {
    companion object {
        // Verdict thresholds on the phishing probability
        const val DANGEROUS_AT = 0.7
        const val SUSPICIOUS_AT = 0.5

        private fun body(json: String, key: String): String =
            Regex("\"$key\"\\s*:\\s*\\[(.*?)]", RegexOption.DOT_MATCHES_ALL).find(json)?.groupValues?.get(1)
                ?: throw IllegalArgumentException("missing $key")

        private fun numbers(json: String, key: String): DoubleArray =
            body(json, key).split(',').map { it.trim() }.filter { it.isNotEmpty() }.map { it.toDouble() }.toDoubleArray()

        private fun strings(json: String, key: String): List<String> =
            Regex("\"([^\"]*)\"").findAll(body(json, key)).map { it.groupValues[1] }.toList()

        private fun number(json: String, key: String): Double =
            Regex("\"$key\"\\s*:\\s*(-?[0-9.eE+-]+)").find(json)?.groupValues?.get(1)?.toDouble()
                ?: throw IllegalArgumentException("missing $key")

        fun fromJson(json: String): UrlMlModel {
            val names = strings(json, "tld_names")
            val rates = numbers(json, "tld_rates")
            require(names.size == rates.size) { "tld_names and tld_rates differ in length" }
            val vocab = FeatureExtractor.Vocab(
                susTld = strings(json, "sus_tld").toSet(),
                freeHosts = strings(json, "free_hosts"),
                brands = strings(json, "brands"),
                secondLevel = strings(json, "second_level").toSet(),
                institution = strings(json, "institution").toSet(),
                tldPrior = number(json, "tld_prior"),
                tldRate = names.zip(rates.toList()).toMap()
            )
            val m = UrlMlModel(
                strings(json, "features"), numbers(json, "mean"), numbers(json, "scale"), numbers(json, "coef"),
                number(json, "intercept"), vocab
            )
            require(m.features == FeatureExtractor.FEATURE_NAMES) { "feature list mismatch" }
            require(m.mean.size == m.features.size && m.scale.size == m.features.size && m.coef.size == m.features.size) { "bad array size" }
            return m
        }
    }

    fun extract(url: String): DoubleArray = FeatureExtractor.extract(url, vocab)

    /** Probability (0..1) that [url] is phishing. Only the host name counts, so /login/ paths cannot raise it. */
    fun predict(url: String): Double = predictFeatures(extract(url))

    fun predictFeatures(x: DoubleArray): Double {
        var z = intercept
        for (i in x.indices) z += coef[i] * ((x[i] - mean[i]) / scale[i])
        return 1.0 / (1.0 + exp(-z))
    }
}
