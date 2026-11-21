package com.example.prism

import com.example.prism.scan.ManualScanAnalyzer
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Trust / Block buttons are shown only for a single URL; message and phone results get just "I Understand". */
class SiteActionsTest {
    /** Same mapping MainActivity uses: the detected kind decides the popup type string. */
    private fun shown(input: String) = showSiteActions(ManualScanAnalyzer.detectKind(input).name.lowercase())

    @Test fun urlShowsSiteActions() {
        assertTrue(shown("http://www.thenaijatimes.com"))
        assertTrue(shown("https://www.google.com"))
        assertTrue(shown("en.tldp.org/HOWTO/Secure-POP+SSH.html"))
    }

    @Test fun textHidesSiteActions() {
        assertFalse(shown("aaaaa"))
        assertFalse(shown("Your parcel is waiting, visit us today"))
    }

    @Test fun phoneHidesSiteActions() {
        assertFalse(shown("+886 912 345 678"))
        assertFalse(shown("0912345678"))
    }
}
