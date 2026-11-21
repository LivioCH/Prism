package com.example.prism.scan

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AutoProtectionPolicyTest {
    @Test fun armedNeedsPlusSwitchAndLogin() {
        assertTrue(AutoProtectionPolicy.armed("PLUS", switchOn = true, hasToken = true))
        assertFalse("Free plan", AutoProtectionPolicy.armed("FREE", true, true))
        assertFalse("no plan chosen", AutoProtectionPolicy.armed(null, true, true))
        assertFalse("switch off", AutoProtectionPolicy.armed("PLUS", false, true))
        assertFalse("logged out", AutoProtectionPolicy.armed("PLUS", true, false))
    }

    @Test fun googleOnlyForATappedLinkWhileArmed() {
        assertTrue(AutoProtectionPolicy.useGoogle(armed = true, interactive = true))
        assertFalse("link merely on screen", AutoProtectionPolicy.useGoogle(true, false))
        assertFalse("not armed, even if tapped", AutoProtectionPolicy.useGoogle(false, true))
        assertFalse(AutoProtectionPolicy.useGoogle(false, false))
    }

    @Test fun passiveResultIsNotCachedWhileArmedSoTheTapStillReachesGoogle() {
        assertFalse(AutoProtectionPolicy.passiveResultCacheable(armed = true, interactive = false))
        assertTrue("tapped: CombinedScan decides", AutoProtectionPolicy.passiveResultCacheable(true, true))
        assertTrue("not armed: caching unchanged", AutoProtectionPolicy.passiveResultCacheable(false, false))
        assertTrue(AutoProtectionPolicy.passiveResultCacheable(false, true))
    }
}
