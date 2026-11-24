package com.example.prism.net

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The Google link check response from prism-backend (POST /api/scans/webrisk) turns into readable reasons. */
class WebRiskParseTest {
    @Test
    fun listedLinkIsReported() {
        val r = ApiClient.parseWebRisk(JSONObject("""
            {"isDangerous":true,
             "scan":{"details":"Google lists evil-login.xyz as a phishing site","threat":"danger"},
             "results":[
               {"url":"http://evil-login.xyz/verify","threatTypes":["SOCIAL_ENGINEERING","MALWARE"],"threats":["phishing","malware"]},
               {"url":"https://www.google.com","threatTypes":[],"threats":[]}]}
        """))
        assertTrue(r.isDangerous)
        assertEquals("Google lists evil-login.xyz as a phishing site", r.details)
        assertEquals(
            listOf(
                "http://evil-login.xyz/verify: Google lists it as phishing and malware" to true,
                "https://www.google.com: not on Google's list of dangerous sites" to false
            ),
            r.reasons
        )
    }

    @Test
    fun automaticCheckReadsTopLevelDetails() {
        val r = ApiClient.parseWebRisk(JSONObject("""
            {"scan":null,"details":"Google lists evil.test as a phishing site","isDangerous":true,
             "results":[{"url":"https://evil.test","threatTypes":["SOCIAL_ENGINEERING"],"threats":["phishing"]}]}
        """))
        assertTrue(r.isDangerous)
        assertEquals("Google lists evil.test as a phishing site", r.details)
    }

    @Test
    fun unlistedLinkIsNotDangerous() {
        val r = ApiClient.parseWebRisk(JSONObject("""
            {"isDangerous":false,"scan":{"details":"This link is not on Google's list of dangerous sites"},
             "results":[{"url":"https://example.com","threatTypes":[],"threats":[]}]}
        """))
        assertFalse(r.isDangerous)
        assertEquals(listOf("https://example.com: not on Google's list of dangerous sites" to false), r.reasons)
    }
}
