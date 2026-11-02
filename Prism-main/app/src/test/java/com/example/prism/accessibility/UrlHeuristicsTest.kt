package com.example.prism.accessibility

import com.example.prism.ThreatLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Behavioural tests for the on-device scoring rules. The numbers are intentionally asserted only
 * at level granularity (SAFE / WARNING / DANGER) so the weights can be tuned without rewriting
 * every test.
 */
class UrlHeuristicsTest {

    private fun levelOf(url: String): ThreatLevel = UrlHeuristics.analyze(url).level

    @Test
    fun `official providers are trusted`() {
        assertEquals(ThreatLevel.SAFE, levelOf("https://www.google.com/search?q=prism"))
        assertEquals(ThreatLevel.SAFE, levelOf("https://www.esunbank.com.tw/member/login"))
        assertEquals(ThreatLevel.SAFE, levelOf("https://esunbank.com/zh-tw/personal"))
        assertEquals(ThreatLevel.SAFE, levelOf("https://www.momoshop.com.tw/goods/123"))
        assertEquals(ThreatLevel.SAFE, levelOf("https://steamcommunity.com/tradeoffer/new"))
    }

    @Test
    fun `ordinary https link stays safe`() {
        val report = UrlHeuristics.analyze("https://example.com/article/42")
        assertEquals(ThreatLevel.SAFE, report.level)
        assertEquals(0, report.score)
    }

    @Test
    fun `raw ip with http and login path is dangerous`() {
        val report = UrlHeuristics.analyze("http://45.33.12.8/login")
        assertEquals(ThreatLevel.DANGER, report.level)
        assertTrue("expected >= danger threshold, was ${report.score}", report.score >= 68)
    }

    @Test
    fun `brand lookalike on disposable tld is dangerous`() {
        val report = UrlHeuristics.analyze("https://paypal-secure-login.tk/verify")
        assertEquals(ThreatLevel.DANGER, report.level)
        assertTrue(report.signals.any { it.label == "Brand impersonation" })
    }

    @Test
    fun `at sign obfuscation is dangerous`() {
        val report = UrlHeuristics.analyze("https://paypal.com@evil-host.tk/login")
        assertEquals(ThreatLevel.DANGER, report.level)
        assertTrue(report.signals.any { it.label == "Disguised destination" })
    }

    @Test
    fun `discord steam gift scam is dangerous`() {
        assertEquals(ThreatLevel.DANGER, levelOf("https://discord-gift-nitro.com/claim"))
    }

    @Test
    fun `taiwan bank lookalike is at least a warning`() {
        val report = UrlHeuristics.analyze("https://esunbank-verify.com/member")
        assertNotEquals(ThreatLevel.SAFE, report.level)
        assertTrue(report.signals.any { it.label == "Brand lookalike" })
    }

    @Test
    fun `punycode homograph is flagged`() {
        assertNotEquals(ThreatLevel.SAFE, levelOf("https://xn--pypal-4ve.com/login"))
    }

    @Test
    fun `shortened link is flagged as suspicious`() {
        assertEquals(ThreatLevel.WARNING, levelOf("https://bit.ly/3xYzAb"))
    }

    @Test
    fun `open redirect on a trusted host is flagged`() {
        assertEquals(
            ThreatLevel.WARNING,
            levelOf("https://www.google.com/url?url=https://evil.tk/login")
        )
    }

    @Test
    fun `hyphenated brand and loose keywords still warn`() {
        assertNotEquals(ThreatLevel.SAFE, levelOf("https://steamcommunity-gift.com/claim"))
    }

    @Test
    fun `fruit domain mention is not treated as a brand attack`() {
        assertEquals(ThreatLevel.SAFE, levelOf("https://apple-pie-recipe.com"))
    }

    @Test
    fun `unrelated short brand prefix is not a false positive`() {
        assertEquals(ThreatLevel.SAFE, levelOf("https://linear.app"))
    }

    @Test
    fun `scores stay inside the documented range`() {
        val urls = listOf(
            "https://example.com",
            "http://45.33.12.8/login",
            "https://paypal-secure-login.tk/verify?account=1&token=abc",
            "https://xn--pypal-4ve.com",
            "https://bit.ly/3xYzAb"
        )
        urls.forEach { url ->
            val score = UrlHeuristics.analyze(url).score
            assertTrue("score out of range for $url: $score", score in 0..100)
        }
    }

    @Test
    fun `trusted check accepts subdomains only with label boundary`() {
        assertTrue(UrlHeuristics.isTrustedHost("accounts.google.com"))
        assertTrue(!UrlHeuristics.isTrustedHost("google.com.evil.tk"))
    }
}
