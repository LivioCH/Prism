package com.example.prism.scan

import kotlin.math.exp

/**
 * Logistic-regression URL model, plain arithmetic only (no ML library, no network).
 * Weights live in assets/url_model.json. Parsing is a tiny regex reader on purpose, so the same
 * code runs in unit tests (no Android org.json needed).
 */
class UrlMlModel(
    val features: List<String>,
    private val mean: DoubleArray,
    private val scale: DoubleArray,
    private val coef: DoubleArray,
    private val intercept: Double,
    val susTld: Set<String>,
    val keywords: List<String>
) {
    companion object {
        // Verdict thresholds on the phishing probability
        const val DANGEROUS_AT = 0.7
        const val SUSPICIOUS_AT = 0.5

        private fun numbers(json: String, key: String): DoubleArray {
            val body = Regex("\"$key\"\\s*:\\s*\\[(.*?)]", RegexOption.DOT_MATCHES_ALL).find(json)?.groupValues?.get(1)
                ?: throw IllegalArgumentException("missing $key")
            return body.split(',').map { it.trim() }.filter { it.isNotEmpty() }.map { it.toDouble() }.toDoubleArray()
        }

        private fun strings(json: String, key: String): List<String> {
            val body = Regex("\"$key\"\\s*:\\s*\\[(.*?)]", RegexOption.DOT_MATCHES_ALL).find(json)?.groupValues?.get(1)
                ?: throw IllegalArgumentException("missing $key")
            return Regex("\"([^\"]*)\"").findAll(body).map { it.groupValues[1] }.toList()
        }

        fun fromJson(json: String): UrlMlModel {
            val intercept = Regex("\"intercept\"\\s*:\\s*(-?[0-9.eE+-]+)").find(json)?.groupValues?.get(1)?.toDouble()
                ?: throw IllegalArgumentException("missing intercept")
            val m = UrlMlModel(
                strings(json, "features"), numbers(json, "mean"), numbers(json, "scale"), numbers(json, "coef"),
                intercept, strings(json, "sus_tld").toSet(), strings(json, "keywords")
            )
            require(m.features.size == FeatureExtractor.FEATURE_NAMES.size && m.features == FeatureExtractor.FEATURE_NAMES) { "feature list mismatch" }
            require(m.mean.size == m.features.size && m.scale.size == m.features.size && m.coef.size == m.features.size) { "bad array size" }
            return m
        }
    }

    fun extract(url: String): DoubleArray = FeatureExtractor.extract(url, susTld, keywords)

    /** Probability (0..1) that [url] is phishing. */
    fun predict(url: String): Double = predictFeatures(extract(url))

    fun predictFeatures(x: DoubleArray): Double {
        var z = intercept
        for (i in x.indices) z += coef[i] * ((x[i] - mean[i]) / scale[i])
        return 1.0 / (1.0 + exp(-z))
    }
}
