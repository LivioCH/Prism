package com.example.prism

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class GoogleBadgeTest {
    @Test fun on() = assertEquals("Google check: ON", googleBadgeText(true))
    @Test fun off() = assertEquals("Google check: OFF", googleBadgeText(false))
    @Test fun unknownShowsNothing() = assertNull(googleBadgeText(null))

    @Test fun headerChipSaysWhereItIsNotConnected() {
        assertEquals("Google check: ON", googleHeaderText(true, isAdmin = false))
        assertEquals("Google API not connected", googleHeaderText(false, isAdmin = false))
        assertEquals("Google API not connected · tap to set up", googleHeaderText(false, isAdmin = true))
        assertNull("unknown (offline) shows nothing", googleHeaderText(null, isAdmin = true))
    }
}
