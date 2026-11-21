package com.example.prism

import com.example.prism.net.ApiClient
import com.example.prism.net.GoogleKeyStatus
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GoogleApiTabTest {
    @Test fun realLookingKeyPasses() = assertTrue(looksLikeGoogleKey("AIza" + "x".repeat(35)))
    @Test fun spacesAroundThePastedKeyAreIgnored() = assertTrue(looksLikeGoogleKey("  AIza" + "x".repeat(35) + "\n"))
    @Test fun shortOrOddTextIsRejected() {
        assertFalse(looksLikeGoogleKey("short"))
        assertFalse(looksLikeGoogleKey("AIza has spaces inside the key value....."))
        assertFalse(looksLikeGoogleKey(""))
    }

    @Test fun sourceTexts() {
        assertEquals("Checking with the server...", googleSourceText(null))
        assertTrue(googleSourceText(GoogleKeyStatus(false, "none", null)).startsWith("No key yet"))
        assertTrue(googleSourceText(GoogleKeyStatus(true, "app", "AIza...x1Yz")).contains("this app (AIza...x1Yz)"))
        assertTrue(googleSourceText(GoogleKeyStatus(true, "env", "AIza...x1Yz")).contains(".env"))
    }

    @Test fun parsesTheServerReply() {
        val on = ApiClient.parseGoogleKey(JSONObject("""{"google":{"active":true,"source":"app","hint":"AIza...xxxx"}}"""))
        assertEquals(GoogleKeyStatus(true, "app", "AIza...xxxx"), on)
        val off = ApiClient.parseGoogleKey(JSONObject("""{"google":{"active":false,"source":"none","hint":null}}"""))
        assertEquals(GoogleKeyStatus(false, "none", null), off)
    }
}
