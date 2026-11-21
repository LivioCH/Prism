package com.example.prism.scan

import com.example.prism.ScanReason
import com.example.prism.ThreatLevel
import com.example.prism.net.ApiException
import com.example.prism.net.GoogleQuota
import com.example.prism.net.WebRiskResult
import kotlinx.coroutines.CancellationException

/**
 * What the Premium check (Google Web Risk) did for one scan. Shown as a badge on the result.
 * The "Normal scan" (on the phone) always runs, so it has no status of its own.
 */
enum class GoogleStatus {
    NOT_APPLICABLE,   // nothing for Google to check (phone number, text without links) or not asked
    CHECKED,          // Google answered
    LIMIT_REACHED,    // Free plan: today's Premium checks are used up, Normal scan only
    UNAVAILABLE       // offline / backend or Google down, Normal scan only
}

/** How the online Google Web Risk check went for one scan. */
sealed interface GoogleCheck {
    /** Google answered. */
    data class Done(val result: WebRiskResult) : GoogleCheck
    /** The Free plan's daily Premium checks are used up (backend answered 429 daily_limit). */
    data class LimitReached(val limit: Int? = null, val resetsAt: Long? = null) : GoogleCheck
    /** Offline, backend down, Google failed, not logged in ... */
    /** [tellUser]: show a note. Only for things the user can fix (signed out); server setup and network stay silent. */
    data class Unavailable(val why: String, val tellUser: Boolean = false) : GoogleCheck
}

/**
 * Joins the two scanners into one result.
 *
 *   Normal scan (on the phone, always runs)  +  Premium check (Google Web Risk, online, for the links found)
 *
 * Rules:
 *  - The final verdict is the worse of the two. Google can only RAISE a verdict: "not listed" means
 *    Google has not reported the site, it never proves the site is safe.
 *  - Google being unavailable or the Free limit being reached never fails the scan. The on-device
 *    result is shown with a note, and it is not cached so the link gets its Premium check next time.
 *  - Only the links are sent to the backend, never the text of a message.
 *
 * Nothing here touches the network or Android: the caller passes the check in as a function.
 */
object CombinedScan {
    const val CHECKED_NOTE = "Premium check: checked online by Google Web Risk"
    const val NOT_PROOF_NOTE = "Not listed means Google hasn't reported the site, not that it is proven safe"
    const val LIMIT_NOTE = "Premium check used up for today: switched to Normal scan. Upgrade to Plus for unlimited checks"
    private const val UNAVAILABLE_NOTE = "Premium check unavailable"

    /** One entry per link Manual Scan found (whitespace removed). Empty for phone numbers and plain text. */
    fun linksForGoogle(manual: ManualScanOutcome): List<String> =
        manual.urlResults.map { r -> r.url.filterNot { it.isWhitespace() } }.filter { it.isNotEmpty() }.distinct()

    fun fromError(e: Exception): GoogleCheck = when {
        e is ApiException && e.code == "daily_limit" -> GoogleCheck.LimitReached(
            limit = e.extra?.takeIf { it.has("limit") && !it.isNull("limit") }?.optInt("limit"),
            resetsAt = e.extra?.takeIf { it.has("resetsAt") && !it.isNull("resetsAt") }?.optLong("resetsAt")
        )
        e is ApiException -> GoogleCheck.Unavailable(e.message ?: "request failed", tellUser = e.code == "unauthorized")
        else -> GoogleCheck.Unavailable("cannot reach the server")
    }

    /**
     * Adds the Google check to a Manual Scan result. [check] receives the links (space separated)
     * and returns Google's answer; any exception it throws becomes a note, never a failed scan.
     */
    suspend fun run(manual: ManualScanOutcome, check: suspend (String) -> WebRiskResult): ManualScanOutcome {
        val links = linksForGoogle(manual)
        if (links.isEmpty()) return manual   // nothing Google can check
        val google = try {
            GoogleCheck.Done(check(links.joinToString(" ")))
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            fromError(e)
        }
        return merge(manual, google)
    }

    fun merge(manual: ManualScanOutcome, google: GoogleCheck): ManualScanOutcome = when (google) {
        is GoogleCheck.Done -> {
            val r = google.result
            val listed = r.reasons.filter { it.second }.map { ScanReason("web_risk", it.first, 100, "high") }
                .ifEmpty { if (r.isDangerous) listOf(ScanReason("web_risk", r.details, 100, "high")) else emptyList() }
            val notes: List<String> =
                if (r.isDangerous) listOf(CHECKED_NOTE) else listOf(CHECKED_NOTE, NOT_PROOF_NOTE)
            manual.copy(
                // Google can only raise the verdict
                threat = if (r.isDangerous) ThreatLevel.DANGER else manual.threat,
                // Google's findings first; "nothing found" would contradict them
                reasons = if (listed.isEmpty()) manual.reasons
                          else listed + manual.reasons.filter { it.rule != "no_issues" },
                infoLines = manual.infoLines + notes,
                cacheable = true,
                googleStatus = GoogleStatus.CHECKED,
                googleQuota = r.quota
            )
        }
        is GoogleCheck.LimitReached -> manual.copy(
            infoLines = manual.infoLines + LIMIT_NOTE,
            cacheable = false,
            googleStatus = GoogleStatus.LIMIT_REACHED,
            // used up: 0 left now, whatever the server's limit is (unknown limit shows as 0)
            googleQuota = GoogleQuota(unlimited = false, limit = google.limit ?: 0, used = google.limit ?: 0, resetsAt = google.resetsAt)
        )
        is GoogleCheck.Unavailable -> manual.copy(
            // Silent fallback: the user still gets the Normal scan result, without a technical
            // message ("not set up", "cannot reach the server"). Signed out is the exception: they can fix it.
            infoLines = if (google.tellUser) manual.infoLines + "$UNAVAILABLE_NOTE (${google.why}): switched to Normal scan" else manual.infoLines,
            cacheable = false,
            googleStatus = GoogleStatus.UNAVAILABLE
        )
    }
}
