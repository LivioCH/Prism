package com.example.prism.scan

/**
 * Free plan: 10 manual scans per rolling 24 hours. Free scans run only on the phone (no Google check),
 * so the phone counts them itself. [times] are the epoch-ms times of earlier scans.
 *
 * Pure logic (no Android), so it is unit tested.
 */
object FreeScanLimit {
    const val PER_DAY = 10
    const val WINDOW_MS = 24L * 60 * 60 * 1000

    /** Only the scans still inside the 24h window, oldest first. */
    fun recent(times: List<Long>, now: Long): List<Long> = times.filter { now - it < WINDOW_MS }.sorted()

    fun remaining(times: List<Long>, now: Long): Int = (PER_DAY - recent(times, now).size).coerceAtLeast(0)

    /** When the next scan frees up (the oldest one leaves the window), or null if none was used. */
    fun resetsAt(times: List<Long>, now: Long): Long? = recent(times, now).firstOrNull()?.plus(WINDOW_MS)

    /** "4,5,6" <-> list, for SharedPreferences. */
    fun decode(s: String?): List<Long> = s.orEmpty().split(',').mapNotNull { it.trim().toLongOrNull() }
    fun encode(times: List<Long>): String = times.joinToString(",")
}
