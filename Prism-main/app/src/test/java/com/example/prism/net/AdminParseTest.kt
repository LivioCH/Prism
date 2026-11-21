package com.example.prism.net

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replies of the admin endpoints of prism-backend turn into the objects the admin screen shows. */
class AdminParseTest {
    @Test
    fun accountListIsParsed() {
        val list = ApiClient.parseAdminUsers(JSONObject("""
            {"users":[
              {"id":"a1","name":"Admin","email":"admin@gmail.com","plan":"PLUS","clipboardMonitoring":true,"isAdmin":true,"createdAt":1795261698154,"scanCount":3},
              {"id":"b2","name":"Budi","email":"budi@x.com","plan":null,"clipboardMonitoring":true,"isAdmin":false,"createdAt":1795261700000,"scanCount":0}]}
        """))
        assertEquals(2, list.size)
        assertEquals(AdminUser("a1", "Admin", "admin@gmail.com", "PLUS", true, 3, 1795261698154), list[0])
        assertNull("no plan chosen yet", list[1].plan)
        assertFalse(list[1].isAdmin)
    }

    @Test
    fun planChangeReplyWithoutScanCountStillParses() {
        val u = ApiClient.parseAdminUser(JSONObject("""
            {"id":"b2","name":"Budi","email":"budi@x.com","plan":"PLUS","clipboardMonitoring":true,"isAdmin":false,"createdAt":1}
        """))
        assertEquals("PLUS", u.plan)
        assertEquals(0, u.scanCount)
    }

    @Test
    fun quotaIsParsedForFreeAndPlus() {
        val free = ApiClient.parseQuota(JSONObject("""{"unlimited":false,"limit":10,"used":3,"remaining":7,"resetsAt":123456}"""))
        assertEquals(GoogleQuota(false, 10, 3, 123456L), free)
        assertEquals(7, free.remaining)
        val plus = ApiClient.parseQuota(JSONObject("""{"unlimited":true,"limit":null,"used":0,"remaining":null,"resetsAt":null}"""))
        assertTrue(plus.unlimited)
        assertNull(plus.resetsAt)
    }

    @Test
    fun webRiskReplyCarriesTheQuotaWhenPresent() {
        val body = """{"isDangerous":false,"scan":{"details":"d"},"results":[{"url":"https://a.com","threats":[]}]%s}"""
        assertEquals(
            GoogleQuota(false, 10, 1, 99L),
            ApiClient.parseWebRisk(JSONObject(body.format(""","quota":{"unlimited":false,"limit":10,"used":1,"remaining":9,"resetsAt":99}"""))).quota
        )
        assertNull("older backend", ApiClient.parseWebRisk(JSONObject(body.format(""))).quota)
    }

    @Test
    fun loginTellsWhetherTheUserIsAdmin() {
        fun login(isAdmin: String) = ApiClient.auth(JSONObject("""
            {"token":"t","user":{"id":"1","name":"N","email":"e@x.com","plan":"FREE"$isAdmin}}
        """))
        assertTrue(login(""","isAdmin":true""").isAdmin)
        assertFalse(login(""","isAdmin":false""").isAdmin)
        assertFalse("older backend without the field", login("").isAdmin)
    }
}
