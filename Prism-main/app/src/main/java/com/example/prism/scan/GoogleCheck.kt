package com.example.prism.scan

import com.example.prism.ScanReason
import com.example.prism.ScanType
import com.example.prism.ThreatLevel
import com.example.prism.net.ApiClient
import com.example.prism.net.ApiException
import com.example.prism.net.WebRiskResult

/**
 * Adds a Google Web Risk check (through prism-backend) to the automatic scans: Screen Shield and the
 * clipboard Auto-Protection. Blocks on the network, so call it off the main thread.
 *
 * Google can only make a verdict worse: a listed link becomes DANGER. If Google can't be asked (not
 * logged in, backend not running, Free plan for the clipboard), the on-device verdict stays as it is
 * and a note says why.
 */
object GoogleCheck {
    const val UNAVAILABLE = "Google check unavailable"

    fun addTo(
        outcome: ManualScanOutcome,
        url: String,
        token: String?,
        source: String,
        check: (token: String, url: String, source: String) -> WebRiskResult = { t, u, s ->
            ApiClient.webRiskCheck(t, u, s, ApiClient.AUTO_CHECK_TIMEOUT_MS)
        }
    ): ManualScanOutcome {
        if (outcome.kind != ScanType.URL) return outcome
        if (outcome.threat == ThreatLevel.DANGER) return outcome          // already blocked, no need to ask Google
        if (token == null) return outcome.copy(infoLines = outcome.infoLines + "$UNAVAILABLE: not logged in")

        val r = try {
            check(token, url, source)
        } catch (e: Exception) {
            val why = if (e is ApiException) e.message else "backend not reachable"
            return outcome.copy(infoLines = outcome.infoLines + "$UNAVAILABLE: $why")
        }
        if (!r.isDangerous) {
            return outcome.copy(infoLines = outcome.infoLines + "Google Web Risk: not on Google's list of dangerous sites")
        }
        return outcome.copy(
            threat = ThreatLevel.DANGER,
            reasons = listOf(ScanReason("web_risk", r.details, 100, "high")) + outcome.reasons.filter { it.rule != "no_issues" },
            infoLines = outcome.infoLines + "Checked online by Google Web Risk"
        )
    }

    /** False when Google could not be asked, so the result is not cached and Google is tried again next time. */
    fun canCache(outcome: ManualScanOutcome): Boolean = outcome.infoLines.none { it.startsWith(UNAVAILABLE) }
}
