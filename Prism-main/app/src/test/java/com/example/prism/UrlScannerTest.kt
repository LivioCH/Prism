package com.example.prism

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UrlScannerTest {
    private fun rank(t: ThreatLevel) = when (t) { ThreatLevel.SAFE -> 0; ThreatLevel.WARNING -> 1; ThreatLevel.DANGER -> 2 }

    @Test
    fun badLinksAreNotSafe() {
        val cases = listOf(
            "http://plurebo-verify.xyz" to ThreatLevel.WARNING,
            "https://plurebo-secure-login.top" to ThreatLevel.WARNING,
            "https://plurebo.com.account-verify.online" to ThreatLevel.DANGER,
            "https://plureb0-login.xyz" to ThreatLevel.WARNING,
            "http://185.220.101.45/login" to ThreatLevel.WARNING
        )
        for (advanced in listOf(false, true)) for ((url, min) in cases) {
            val r = UrlScanner.scan(url, advanced)
            assertTrue("$url -> ${r.threat} (${r.score})", rank(r.threat) >= rank(min))
            assertTrue(r.reasons.isNotEmpty())
        }
    }

    @Test
    fun controlLinksStaySafeWithPositiveReason() {
        val safe = listOf("https://www.google.com", "https://github.com", "https://www.wikipedia.org", "https://airline.com", "https://pineapple.com")
        for (advanced in listOf(false, true)) for (url in safe) {
            val r = UrlScanner.scan(url, advanced)
            assertEquals("$url -> ${r.score}", ThreatLevel.SAFE, r.threat)
            assertTrue(r.reasons.first().detail.contains("No obvious suspicious features"))
        }
    }

    @Test
    fun brandMatchIsWholeLabelOnly() {
        assertFalse(UrlScanner.scan("https://airline.com").reasons.any { it.rule == "brand_impersonation" })
        assertTrue(UrlScanner.scan("https://paypal-login.top").reasons.any { it.rule == "brand_impersonation" })
    }

    @Test
    fun singlePathKeywordNeverDangerous() {
        for (w in listOf("account", "update", "bank", "secure")) {
            assertEquals(ThreatLevel.SAFE, UrlScanner.scan("https://example.com/$w").threat)
        }
    }

    @Test
    fun redirectChainWithHiddenDomainAtSignAndSpaceIsFlagged() {
        val chain = "http:// t-info.mail.adobe.com/r/?id=xxx&p1=t.mid.accor-mail.com/r/?id=yyy&p1=filepmgklf.com/victim @domain.com"
        assertTrue(UrlScanner.isValidUrl(chain))
        for (advanced in listOf(false, true)) {
            val r = UrlScanner.scan(chain, advanced)
            assertTrue("-> ${r.threat} (${r.score})", rank(r.threat) >= rank(ThreatLevel.WARNING))
            assertFalse(r.reasons.any { it.rule == "invalid_url" })
            assertTrue(r.reasons.any { it.rule == "whitespace" && it.detail.contains("whitespace") })
            assertTrue(r.reasons.any { it.rule == "at_sign" && it.detail.contains("@") })
            assertTrue(r.reasons.any { it.rule == "embedded_url" && it.detail.contains("filepmgklf.com") })
        }
    }

    @Test
    fun atSignInHostPartAnalysesRealHost() {
        val r = UrlScanner.scan("http://www.google.com@evil-site.xyz/login")
        assertTrue(r.reasons.any { it.rule == "userinfo" && it.detail.contains("@") })
        assertTrue(r.reasons.any { it.rule == "risky_tld" && it.detail.contains(".xyz") })
    }

    @Test
    fun hiddenBlocklistedDomainDecidesVerdict() {
        val url = "https://www.google.com/redirect?url=http://evil-hidden.com/x"
        assertEquals(ThreatLevel.DANGER, UrlScanner.scan(url, blocklist = setOf("evil-hidden.com")).threat)
        assertTrue(rank(UrlScanner.scan(url).threat) < rank(ThreatLevel.DANGER))
    }

    @Test
    fun normalQueryStringsAreNotChains() {
        for (u in listOf("https://github.com/search?q=report.pdf&page=2", "https://www.google.com/search?q=hello+world")) {
            assertEquals(u, ThreatLevel.SAFE, UrlScanner.scan(u).threat)
        }
    }

    @Test
    fun gclidInPathIsAtLeastSuspicious() {
        val u = "https://pontosapontamentolu.com/gclid/=/c/?gclid=ishecabh95cvbhb1eiwagy6m4vn7url3tlj5m_nu__lcyj4n06pqquydbh-56148buwwbmv7k1qejboci-isjw5_kiq"
        for (advanced in listOf(false, true)) {
            val r = UrlScanner.scan(u, advanced)
            assertTrue("${r.threat} (${r.score})", rank(r.threat) >= rank(ThreatLevel.WARNING))
            assertTrue(r.reasons.any { it.rule == "tracking_in_path" })
            assertTrue(r.reasons.any { it.rule == "random_query_token" })
            assertTrue(r.reasons.any { it.rule == "long_url" && it.points > 0 })
        }
        // a real gclid lives in the query only
        assertFalse(UrlScanner.scan("https://www.google.com/?gclid=abc").reasons.any { it.rule == "tracking_in_path" })
    }

    @Test
    fun invalidInputIsRejectedByValidator() {
        assertFalse(UrlScanner.isValidUrl(""))
        assertFalse(UrlScanner.isValidUrl("not a url"))
        assertFalse(UrlScanner.isValidUrl("localhost"))
        assertTrue(UrlScanner.isValidUrl("example.com"))
    }
}
