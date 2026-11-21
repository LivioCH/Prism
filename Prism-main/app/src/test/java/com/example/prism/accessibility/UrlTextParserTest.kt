package com.example.prism.accessibility

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM tests for the text-level URL rules. Keeping [UrlTextParser] free of Android imports means
 * these run in milliseconds and can be executed on the build server without an emulator.
 */
class UrlTextParserTest {

    @Test
    fun `finds scheme urls inside a sentence`() {
        val urls = UrlTextParser.findUrls("Open https://secure-bank-login.com/verify?account=1 now")
        assertEquals(listOf("https://secure-bank-login.com/verify?account=1"), urls)
    }

    @Test
    fun `finds www and bare domains`() {
        assertEquals(
            listOf("www.example.com.tw/promo"),
            UrlTextParser.findUrls("Visit www.example.com.tw/promo today")
        )
        assertEquals(
            listOf("esunbank.com.tw/member"),
            UrlTextParser.findUrls("Login at esunbank.com.tw/member now")
        )
    }

    @Test
    fun `finds scheme-less high risk tlds shown by browsers`() {
        assertEquals(
            listOf("paypal-secure-login.tk"),
            UrlTextParser.findUrls("paypal-secure-login.tk")
        )
        assertEquals(
            listOf("esunbank-verify.ml/login"),
            UrlTextParser.findUrls("esunbank-verify.ml/login")
        )
    }

    @Test
    fun `ignores decimals and plain file names`() {
        val urls = UrlTextParser.findUrls("Version 2.0 is out, see readme.md and file.zip")
        assertTrue("Unexpected matches: $urls", urls.isEmpty())
    }

    @Test
    fun `keeps multiple links in one message`() {
        val urls = UrlTextParser.findUrls("https://a.example.com and http://b.example.org/x")
        assertEquals(listOf("https://a.example.com", "http://b.example.org/x"), urls)
    }

    @Test
    fun `trims sentence punctuation`() {
        assertEquals(
            listOf("https://example.com/page"),
            UrlTextParser.findUrls("See https://example.com/page).")
        )
        assertEquals(
            listOf("https://example.com"),
            UrlTextParser.findUrls("Go to https://example.com.")
        )
    }

    @Test
    fun `reverses bracketed dot and hxxp evasions`() {
        assertEquals(
            listOf("http://evil.com/login"),
            UrlTextParser.findUrls("Click hxxp://evil[.]com/login")
        )
        assertEquals(
            listOf("paypal.com"),
            UrlTextParser.findUrls("Please check paypal dot com")
        )
    }

    @Test
    fun `stops before chinese text glued to the link`() {
        assertEquals(
            listOf("https://evil.example.com"),
            UrlTextParser.findUrls("點擊https://evil.example.com領取獎品")
        )
    }

    @Test
    fun `parses host user info and port`() {
        assertEquals("evil.tk", UrlTextParser.hostOf("https://paypal.com@evil.tk/login"))
        assertEquals("paypal.com", UrlTextParser.userInfoOf("https://paypal.com@evil.tk/login"))
        assertEquals("example.com", UrlTextParser.hostOf("example.com"))
        assertEquals(8080, UrlTextParser.portOf("http://example.com:8080/path"))
        assertNull(UrlTextParser.portOf("https://example.com/path"))
    }

    @Test
    fun `resolves registrable domains including com tw`() {
        assertEquals("esunbank.com.tw", UrlTextParser.registrableDomain("www.esunbank.com.tw"))
        assertEquals("example.com", UrlTextParser.registrableDomain("a.b.example.com"))
        assertEquals("example.co.uk", UrlTextParser.registrableDomain("shop.example.co.uk"))
        assertEquals("example.com", UrlTextParser.registrableDomain("example.com"))
    }

    @Test
    fun `recognises open redirect parameters`() {
        assertTrue(UrlTextParser.isOpenRedirect("url=https%3A%2F%2Fevil.com"))
        assertTrue(UrlTextParser.isOpenRedirect("next=//evil.example"))
        assertFalse(UrlTextParser.isOpenRedirect("q=prism+anti+phishing"))
    }

    @Test
    fun `cache key is normalised`() {
        assertEquals("https://example.com/a", UrlTextParser.cacheKey("HTTPS://Example.com/a/"))
    }

    @Test
    fun `ip literals are recognised`() {
        assertTrue(UrlTextParser.isIpLiteral("45.33.12.8"))
        assertTrue(UrlTextParser.isIpLiteral("2001:db8::1"))
        assertFalse(UrlTextParser.isIpLiteral("example.com"))
    }
}
