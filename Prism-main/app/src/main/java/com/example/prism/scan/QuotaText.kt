package com.example.prism.scan

import com.example.prism.net.GoogleQuota

/** Wording for the Premium check quota, kept out of the UI so it can be tested. */
object QuotaText {
    /** "3 h 20 min", "45 min", "less than a minute". */
    fun resetsIn(resetsAt: Long?, now: Long = System.currentTimeMillis()): String? {
        if (resetsAt == null) return null
        val minutes = ((resetsAt - now) / 60_000).coerceAtLeast(0)
        return when {
            minutes < 1 -> "less than a minute"
            minutes < 60 -> "$minutes min"
            else -> "${minutes / 60} h ${minutes % 60} min"
        }
    }

    /** Short pill next to "Premium check": "Unlimited", "7 of 10 left", "0 left". */
    fun pill(q: GoogleQuota): String = when {
        q.unlimited -> "Unlimited"
        q.limit > 0 -> "${q.remaining} of ${q.limit} left"
        else -> "${q.remaining} left"
    }

    /** One sentence under the chips on a result / on the Scan tab. */
    fun line(q: GoogleQuota, now: Long = System.currentTimeMillis()): String = when {
        q.unlimited -> "Premium check: unlimited with Plus"
        q.exhausted -> "Premium checks used up for today. Next one in ${resetsIn(q.resetsAt, now) ?: "a while"}. Upgrade to Plus for unlimited"
        else -> "Premium checks left today: ${pill(q).removeSuffix(" left")}"
    }

    /** Toast right after a scan: the last check was just used, or the scan fell back to Normal scan. */
    fun lastUsedTitle() = "Last Premium check used"
    fun lastUsedBody(q: GoogleQuota, now: Long = System.currentTimeMillis()) =
        "Next scans use Normal scan only. A check frees up in ${resetsIn(q.resetsAt, now) ?: "a while"}."
    fun usedUpTitle() = "Premium check used up"
    fun usedUpBody(q: GoogleQuota?, now: Long = System.currentTimeMillis()) =
        "Switched to Normal scan. Resets in ${resetsIn(q?.resetsAt, now) ?: "a while"}, or upgrade to Plus for unlimited."
}
