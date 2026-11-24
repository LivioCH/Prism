package com.example.prism.scan

import com.example.prism.ScanReason
import com.example.prism.ScanType
import com.example.prism.ThreatLevel
import com.example.prism.net.ApiException
import com.example.prism.net.WebRiskResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.ConnectException

/** Google Web Risk added to the automatic scans (Screen Shield, clipboard Auto-Protection). */
class GoogleCheckTest {
    private val safeUrl = ManualScanOutcome(
        ScanType.URL, ThreatLevel.SAFE, listOf(ScanReason("no_issues", "No obvious suspicious features", 0, "low")), emptyList()
    )
    private val calls = mutableListOf<Triple<String, String, String>>()
    private fun google(listed: Boolean): (String, String, String) -> WebRiskResult = { t, u, s ->
        calls += Triple(t, u, s)
        WebRiskResult(listed, if (listed) "Google lists evil.test as a phishing site" else "This link is not on Google's list", emptyList())
    }

    @Test
    fun aLinkGoogleListsBecomesDangerous() {
        val r = GoogleCheck.addTo(safeUrl, "https://evil.test", "tok", "screen", google(listed = true))
        assertEquals(ThreatLevel.DANGER, r.threat)
        assertEquals("Google lists evil.test as a phishing site", r.reasons.first().detail)
        assertTrue(r.reasons.none { it.rule == "no_issues" })
        assertEquals(listOf(Triple("tok", "https://evil.test", "screen")), calls)
        assertTrue(GoogleCheck.canCache(r))
    }

    @Test
    fun anUnlistedLinkKeepsTheOnDeviceVerdict() {
        val warning = safeUrl.copy(threat = ThreatLevel.WARNING)
        val r = GoogleCheck.addTo(warning, "https://a.test", "tok", "clipboard", google(listed = false))
        assertEquals(ThreatLevel.WARNING, r.threat)                 // Google never makes a verdict better
        assertTrue(r.infoLines.single().startsWith("Google Web Risk: not on"))
    }

    @Test
    fun noGoogleCallWhenNotNeededOrNotPossible() {
        val danger = safeUrl.copy(threat = ThreatLevel.DANGER)
        assertEquals(danger, GoogleCheck.addTo(danger, "https://a.test", "tok", "screen", google(true)))
        val phone = safeUrl.copy(kind = ScanType.PHONE)
        assertEquals(phone, GoogleCheck.addTo(phone, "+886912345678", "tok", "screen", google(true)))
        val noLogin = GoogleCheck.addTo(safeUrl, "https://a.test", null, "screen", google(true))
        assertEquals(ThreatLevel.SAFE, noLogin.threat)
        assertTrue(calls.isEmpty())
        assertFalse(GoogleCheck.canCache(noLogin))
    }

    @Test
    fun aFailedGoogleCallKeepsTheVerdictAndIsNotCached() {
        val down = GoogleCheck.addTo(safeUrl, "https://a.test", "tok", "screen") { _, _, _ -> throw ConnectException("refused") }
        assertEquals(ThreatLevel.SAFE, down.threat)
        assertEquals("Google check unavailable: backend not reachable", down.infoLines.single())
        assertFalse(GoogleCheck.canCache(down))
        val free = GoogleCheck.addTo(safeUrl, "https://a.test", "tok", "clipboard") { _, _, _ ->
            throw ApiException("upgrade_required", "Clipboard monitoring is a Prism Plus feature")
        }
        assertEquals("Google check unavailable: Clipboard monitoring is a Prism Plus feature", free.infoLines.single())
    }
}
