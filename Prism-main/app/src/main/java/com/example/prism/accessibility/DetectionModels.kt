package com.example.prism.accessibility

import com.example.prism.ThreatLevel

/** Where a screen verdict came from - kept for diagnostics and future UI badges. */
enum class VerdictSource {
    /** The user trusted the host; the database short-circuited the scan. */
    WHITELIST,

    /** The user blocked the host; always dangerous. */
    BLACKLIST,

    /** A previous result from the encrypted URL cache. */
    CACHE,

    /** Fresh on-device heuristics + ML. */
    LOCAL
}

/** A single reason displayed by the shield overlay. */
data class RiskSignal(
    val label: String,
    val weight: Int,
    val detail: String
)

/** Final decision for one URL, shaped for the accessibility overlay. */
data class UrlVerdict(
    val url: String,
    val host: String?,
    val domain: String?,
    val level: ThreatLevel,
    val score: Int,
    val reason: String,
    val signals: List<RiskSignal> = emptyList(),
    val source: VerdictSource = VerdictSource.LOCAL
)
