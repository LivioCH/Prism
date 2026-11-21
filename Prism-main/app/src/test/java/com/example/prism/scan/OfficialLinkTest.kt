package com.example.prism.scan

import com.example.prism.ThreatLevel
import com.example.prism.UrlScanner
import com.example.prism.accessibility.UrlHeuristics
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Long official login links (Facebook sign-in returning to Instagram) used to be flagged as phishing:
 * the ML model reacts to length/digits/"accounts", and instagram.com was treated as a hidden redirect.
 */
class OfficialLinkTest {
    private val model = UrlMlModel.fromJson(File("src/main/assets/url_model.json").readText())

    private val facebookLogin = "https://www.facebook.com/oidc/?app_id=124024574287414" +
        "&redirect_uri=https%3A%2F%2Fwww.instagram.com%2Faccounts%2Fsignupviafb%2F&response_type=code" +
        "&scope=openid%20email%20profile%20linking&state=ATqvkmXiXTkEmf2P8_6Qtbohe_QGulXupEVQKN1ZG1_VoUT0oRyHfBQ" +
        "bdj9hFPd23SvZOXqM9kHd4pOmsWtoLdhfMlqAHqORwelXVLSfpGSbLlOzsD8bmxQdZVzt2X2DVznKKa2o9xkttDsacxAvMceOzFAt_v7" +
        "SSKq-xULOib2nNnkHZe0-X713rJ-p5iNEc_xmACVLH5MN__feyB-u1G9Rd5CsaRirliTmJBIpYMCg99rKlGGBZIpVwozAiFSKwgVqQM6R" +
        "-kOg_QLurw5G1PueDQ"

    @Test
    fun facebookLoginLinkIsNotFlagged() {
        val r = ManualScanAnalyzer.analyze(facebookLogin, model)
        assertEquals(ThreatLevel.SAFE, r.threat)
        assertTrue(r.reasons.none { it.rule == "ml_model" || it.rule == "embedded_url" })
        assertTrue(r.infoLines.single().endsWith("(not used: official site)"))
        assertEquals(ThreatLevel.SAFE, UrlHeuristics.analyze(facebookLogin).level)   // screen shield too
    }

    @Test
    fun officialSiteRedirectingToAScamIsStillFlagged() {
        val bounce = "https://www.facebook.com/l.php?u=http%3A%2F%2Fevil-login.xyz%2Fverify"
        assertNotEquals(ThreatLevel.SAFE, ManualScanAnalyzer.analyze(bounce, model).threat)
        assertTrue(UrlScanner.scan(bounce).reasons.any { it.rule == "embedded_url" && it.detail.contains("evil-login.xyz") })
        assertNotEquals(ThreatLevel.SAFE, UrlHeuristics.analyze("https://www.facebook.com/x?redirect_uri=https%3A%2F%2Fevil.tk%2Flogin").level)
    }

    @Test
    fun mlStillCountsOffOfficialSitesAndBehindAtTricks() {
        assertFalse(UrlScanner.isOfficialBrandSite("http://www.facebook.com@evil-site.xyz/login"))
        assertFalse(UrlScanner.isOfficialBrandSite("https://facebook-login.top"))
        assertTrue(UrlScanner.isOfficialBrandSite("https://m.facebook.com/x"))
        // the same long address on a look-alike domain keeps the ML verdict
        val fake = facebookLogin.replace("www.facebook.com", "www.faceb00k-login.com")
        assertNotEquals(ThreatLevel.SAFE, ManualScanAnalyzer.analyze(fake, model).threat)
    }
}
