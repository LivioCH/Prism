package com.example.prism.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Free plan: 10 manual scans per rolling 24 hours. */
class FreeScanLimitTest {
    private val now = 1_000_000_000L
    private val hour = 60 * 60 * 1000L

    @Test
    fun startsWithTenAndNothingToWaitFor() {
        assertEquals(10, FreeScanLimit.remaining(emptyList(), now))
        assertNull(FreeScanLimit.resetsAt(emptyList(), now))
    }

    @Test
    fun eachScanInTheLast24hUsesOne() {
        val times = List(10) { now - it * hour }
        assertEquals(0, FreeScanLimit.remaining(times, now))
        // the oldest (9 h ago) frees up 15 h from now
        assertEquals(now - 9 * hour + FreeScanLimit.WINDOW_MS, FreeScanLimit.resetsAt(times, now))
    }

    @Test
    fun scansOlderThan24hNoLongerCount() {
        val times = listOf(now - 25 * hour, now - 30 * hour, now - hour)
        assertEquals(9, FreeScanLimit.remaining(times, now))
        assertEquals(listOf(now - hour), FreeScanLimit.recent(times, now))
    }

    @Test
    fun savedTextRoundTrips() {
        val times = listOf(now, now - hour)
        assertEquals(times, FreeScanLimit.decode(FreeScanLimit.encode(times)))
        assertEquals(emptyList<Long>(), FreeScanLimit.decode(null))
        assertEquals(listOf(5L), FreeScanLimit.decode("x,5,"))
    }
}
