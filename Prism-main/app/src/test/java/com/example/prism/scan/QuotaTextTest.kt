package com.example.prism.scan

import com.example.prism.net.GoogleQuota
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The words shown for the Premium check quota. */
class QuotaTextTest {
    private val now = 1_000_000_000L
    private fun free(used: Int, resetsAt: Long? = null) = GoogleQuota(false, 10, used, resetsAt)

    @Test fun remainingCountsDownAndNeverGoesBelowZero() {
        assertEquals(10, free(0).remaining)
        assertEquals(3, free(7).remaining)
        assertEquals(0, free(10).remaining)
        assertEquals(0, free(14).remaining)
        assertTrue(free(10).exhausted)
        assertFalse(free(9).exhausted)
    }

    @Test fun plusIsNeverExhausted() {
        val plus = GoogleQuota(true, 0, 500, null)
        assertFalse(plus.exhausted)
        assertEquals("Unlimited", QuotaText.pill(plus))
    }

    @Test fun pillAndLine() {
        assertEquals("7 of 10 left", QuotaText.pill(free(3)))
        assertEquals("Premium checks left today: 7 of 10", QuotaText.line(free(3), now))
        assertTrue(QuotaText.line(free(10, now + 3 * 3_600_000L + 20 * 60_000L), now).contains("3 h 20 min"))
        assertTrue(QuotaText.line(free(10), now).contains("Upgrade to Plus"))
    }

    @Test fun resetsInIsReadable() {
        assertNull(QuotaText.resetsIn(null, now))
        assertEquals("less than a minute", QuotaText.resetsIn(now + 20_000, now))
        assertEquals("45 min", QuotaText.resetsIn(now + 45 * 60_000L, now))
        assertEquals("2 h 5 min", QuotaText.resetsIn(now + 125 * 60_000L, now))
        assertEquals("a time in the past reads as soon", "less than a minute", QuotaText.resetsIn(now - 10_000, now))
    }

    @Test fun notificationsMentionTheSwitchToNormalScan() {
        val q = free(10, now + 90 * 60_000L)
        assertTrue(QuotaText.usedUpBody(q, now).contains("Normal scan"))
        assertTrue(QuotaText.usedUpBody(q, now).contains("1 h 30 min"))
        assertTrue(QuotaText.lastUsedBody(q, now).contains("Normal scan"))
    }
}
