package com.example.prism

import org.junit.Assert.assertEquals
import org.junit.Test

class HistoryViewSwitchTest {
    @Test fun noSitesYetShowsPlainLabel() = assertEquals("Trusted & blocked", sitesOptionLabel(0, 0))
    @Test fun countsBothLists() = assertEquals("Trusted & blocked (5)", sitesOptionLabel(2, 3))
}
