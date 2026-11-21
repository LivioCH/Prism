package com.example.prism.scan

import com.example.prism.ScanReason
import com.example.prism.ScanType
import com.example.prism.ThreatLevel
import com.example.prism.net.ApiException
import com.example.prism.net.GoogleQuota
import org.json.JSONObject
import com.example.prism.net.WebRiskResult
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/** Manual Scan + Google Web Risk joined into one verdict. */
class CombinedScanTest {

    private fun url(u: String, t: ThreatLevel = ThreatLevel.SAFE) = UrlResult(u, null, t, emptyList())

    private fun manual(
        threat: ThreatLevel,
        urls: List<String> = listOf("https://example.com"),
        reasons: List<ScanReason> = listOf(ScanReason("no_issues", "No issues", 0, "low"))
    ) = ManualScanOutcome(ScanType.URL, threat, reasons, listOf("ML: 5% phishing probability"), urls.map { url(it, threat) })

    private fun googleSafe(u: String = "https://example.com") =
        WebRiskResult(false, "not listed", listOf("$u: not on Google's list of dangerous sites" to false))

    private fun googleDanger(u: String = "http://evil-login.xyz") =
        WebRiskResult(true, "Google lists evil-login.xyz as a phishing site", listOf("$u: Google lists it as phishing" to true))

    private fun run(m: ManualScanOutcome, check: suspend (String) -> WebRiskResult) = runBlocking { CombinedScan.run(m, check) }

    // ---- verdict rules

    @Test fun googleRaisesASafeVerdictToDanger() {
        val r = run(manual(ThreatLevel.SAFE, listOf("http://evil-login.xyz"))) { googleDanger() }
        assertEquals(ThreatLevel.DANGER, r.threat)
        assertTrue(r.reasons.any { it.rule == "web_risk" && it.severity == "high" })
        assertFalse("'no issues' must not stay next to Google's finding", r.reasons.any { it.rule == "no_issues" })
        assertEquals("Google's finding comes first", "web_risk", r.reasons.first().rule)
        assertTrue(CombinedScan.CHECKED_NOTE in r.infoLines)
    }

    @Test fun googleNeverLowersAVerdict() {
        for (t in ThreatLevel.entries) {
            val r = run(manual(t)) { googleSafe() }
            assertEquals("Google 'not listed' must not change $t", t, r.threat)
        }
    }

    @Test fun notListedKeepsTheCaveat() {
        val r = run(manual(ThreatLevel.SAFE)) { googleSafe() }
        assertTrue(CombinedScan.NOT_PROOF_NOTE in r.infoLines)
        assertTrue(r.reasons.none { it.rule == "web_risk" })
        assertTrue(r.cacheable)
    }

    @Test fun existingManualInfoAndReasonsAreKept() {
        val m = manual(ThreatLevel.WARNING, reasons = listOf(ScanReason("risky_tld", "Risky ending", 20, "medium")))
        val r = run(m) { googleDanger() }
        assertTrue("ML: 5% phishing probability" in r.infoLines)
        assertTrue(r.reasons.any { it.rule == "risky_tld" })
        assertEquals(m.urlResults, r.urlResults)
    }

    // ---- Google cannot finish: the scan must still succeed

    @Test fun dailyLimitKeepsTheManualVerdictAndIsNotCached() {
        val m = manual(ThreatLevel.WARNING)
        val r = run(m) { throw ApiException("daily_limit", "Free plan is limited to 10 scans per day") }
        assertEquals(ThreatLevel.WARNING, r.threat)
        assertEquals(m.reasons, r.reasons)
        assertTrue(CombinedScan.LIMIT_NOTE in r.infoLines)
        assertFalse("must not be cached or the link never gets its Google check", r.cacheable)
    }

    @Test fun backendOrGoogleFailureKeepsTheManualVerdict() {
        for (e in listOf<Exception>(ApiException("webrisk_failed", "Could not reach Google Web Risk"), ApiException("webrisk_unavailable", "not set up"), IOException("timeout"))) {
            val r = run(manual(ThreatLevel.SAFE)) { throw e }
            assertEquals(ThreatLevel.SAFE, r.threat)
            assertFalse(r.cacheable)
            assertTrue(r.infoLines.none { it.contains("Premium check") || it.contains("Google") })
            assertEquals(GoogleStatus.UNAVAILABLE, r.googleStatus)
        }
    }

    @Test fun loggedOutTokenIsReportedNotHidden() {
        val r = run(manual(ThreatLevel.SAFE)) { throw ApiException("unauthorized", "Invalid or expired token") }
        assertTrue(r.infoLines.any { it.contains("Invalid or expired token") })
    }

    // ---- what is sent to Google

    @Test fun phoneNumbersAndPlainTextNeverCallGoogle() {
        var called = false
        val phone = ManualScanOutcome(ScanType.PHONE, ThreatLevel.SAFE, emptyList(), emptyList())
        val text = ManualScanOutcome(ScanType.MESSAGE, ThreatLevel.SAFE, emptyList(), emptyList())
        for (m in listOf(phone, text)) {
            val r = run(m) { called = true; googleSafe() }
            assertEquals(m, r)
        }
        assertFalse(called)
    }

    @Test fun onlyTheLinksAreSentNeverTheMessageText() {
        var sent: String? = null
        val m = ManualScanOutcome(
            ScanType.MESSAGE, ThreatLevel.WARNING, emptyList(), emptyList(),
            listOf(url("https://a.example/x"), url("http://b.example"), url("https://a.example/x"))
        )
        run(m) { sent = it; googleSafe() }
        assertEquals("https://a.example/x http://b.example", sent)
    }

    @Test fun spacesInsideALinkAreRemoved() {
        assertEquals(listOf("http://evil.xyz/login"), CombinedScan.linksForGoogle(manual(ThreatLevel.SAFE, listOf("http://evil.xyz/log in"))))
    }

    // ---- which engine did what (the badges on the result)

    @Test fun statusTellsWhichEnginesRan() {
        val quota = GoogleQuota(unlimited = false, limit = 10, used = 4, resetsAt = 5_000L)
        val checked = run(manual(ThreatLevel.SAFE)) { googleSafe().copy(quota = quota) }
        assertEquals(GoogleStatus.CHECKED, checked.googleStatus)
        assertEquals(quota, checked.googleQuota)
        assertEquals(6, checked.googleQuota!!.remaining)

        val limit = run(manual(ThreatLevel.SAFE)) { throw ApiException("daily_limit", "x", JSONObject("""{"limit":10,"resetsAt":9000}""")) }
        assertEquals(GoogleStatus.LIMIT_REACHED, limit.googleStatus)
        assertTrue(limit.googleQuota!!.exhausted)
        assertEquals(9000L, limit.googleQuota!!.resetsAt)
        assertEquals(10, limit.googleQuota!!.limit)

        val phone = ManualScanOutcome(ScanType.PHONE, ThreatLevel.SAFE, emptyList(), emptyList())
        assertEquals(GoogleStatus.NOT_APPLICABLE, run(phone) { googleSafe() }.googleStatus)
    }

    @Test fun limitWithoutDetailsStillCountsAsUsedUp() {
        val r = run(manual(ThreatLevel.SAFE)) { throw ApiException("daily_limit", "x") }   // older backend, no extras
        assertEquals(GoogleStatus.LIMIT_REACHED, r.googleStatus)
        assertTrue(r.googleQuota!!.exhausted)
    }

    // ---- error mapping

    @Test fun errorMapping() {
        assertEquals(GoogleCheck.LimitReached(), CombinedScan.fromError(ApiException("daily_limit", "x")))
        assertTrue(CombinedScan.fromError(ApiException("webrisk_failed", "boom")) is GoogleCheck.Unavailable)
        assertTrue(CombinedScan.fromError(IOException()) is GoogleCheck.Unavailable)
    }
}
