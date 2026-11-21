package com.example.prism.scan

/**
 * When does the screen monitor use the Google link check?
 *
 *  - Only while **Auto-Protection** is on, which is a Plus feature (Plus plan + the switch + a login).
 *  - Only when the user actually **opens (taps) a link**. Links that merely sit on the screen get the
 *    Normal scan on the phone, which is free and offline. That keeps the number of Google calls small:
 *    one per link the user opens, and the 7-day cache makes repeats free.
 *
 * Pure logic (no Android), so it is unit tested.
 */
object AutoProtectionPolicy {
    /** Auto-Protection is really active for this user. */
    fun armed(plan: String?, switchOn: Boolean, hasToken: Boolean): Boolean =
        plan == "PLUS" && switchOn && hasToken

    /** Ask Google for this link? Only for a tapped link while armed. */
    fun useGoogle(armed: Boolean, interactive: Boolean): Boolean = armed && interactive

    /**
     * May this Normal-only result be remembered? While armed, a passive result must NOT be cached:
     * otherwise the later tap on the same link would hit the cache and skip Google.
     * (A tapped link's cacheability comes from CombinedScan: cached only if Google answered.)
     */
    fun passiveResultCacheable(armed: Boolean, interactive: Boolean): Boolean = !(armed && !interactive)
}
