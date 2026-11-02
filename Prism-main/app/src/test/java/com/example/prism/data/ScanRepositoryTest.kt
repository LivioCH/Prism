package com.example.prism.data

import com.example.prism.ScanReason
import com.example.prism.ScanType
import com.example.prism.ThreatLevel
import com.example.prism.scan.ManualScanAnalyzer
import com.example.prism.scan.UrlMlModel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

// In-memory stand-ins for the Room DAOs, so the pipeline is tested without Android or SQLCipher.
private class FakeHistory : ScanHistoryDao {
    val rows = MutableStateFlow<List<ScanHistoryEntity>>(emptyList())
    override suspend fun insert(row: ScanHistoryEntity): Long { rows.value = rows.value + row.copy(id = rows.value.size + 1L); return rows.value.size.toLong() }
    override fun observeAll(): Flow<List<ScanHistoryEntity>> = rows
    override fun observeTotal(): Flow<Int> = rows.map { it.size }
    override fun observeCount(verdict: String): Flow<Int> = rows.map { r -> r.count { it.verdict == verdict } }
    override suspend fun clear() { rows.value = emptyList() }
}

private class FakeWhitelist : WhitelistDao {
    val rows = MutableStateFlow<List<WhitelistEntity>>(emptyList())
    override suspend fun insert(row: WhitelistEntity): Long {
        if (rows.value.any { it.value == row.value }) return -1   // unique index, IGNORE
        rows.value = rows.value + row; return 1
    }
    override suspend fun delete(value: String) { rows.value = rows.value.filterNot { it.value == value } }
    override suspend fun countMatches(values: List<String>) = rows.value.count { it.value in values }
    override fun observeAll(): Flow<List<WhitelistEntity>> = rows
}

private class FakeBlacklist : BlacklistDao {
    val rows = MutableStateFlow<List<BlacklistEntity>>(emptyList())
    override suspend fun insert(row: BlacklistEntity): Long {
        if (rows.value.any { it.value == row.value }) return -1   // unique index, IGNORE
        rows.value = rows.value + row; return 1
    }
    override suspend fun delete(value: String) { rows.value = rows.value.filterNot { it.value == value } }
    override suspend fun countMatches(values: List<String>) = rows.value.count { it.value in values }
    override suspend fun allValues() = rows.value.map { it.value }
    override fun observeAll(): Flow<List<BlacklistEntity>> = rows
}

private class FakeCache : UrlCacheDao {
    val rows = mutableMapOf<String, UrlCacheEntity>()
    override suspend fun get(key: String) = rows[key]
    override suspend fun put(row: UrlCacheEntity) { rows[row.key] = row }
    override suspend fun deleteOlderThan(olderThan: Long) { rows.values.removeAll { it.cachedAt < olderThan } }
}

class ScanRepositoryTest {
    private val model = UrlMlModel.fromJson(File("src/main/assets/url_model.json").readText())
    private val history = FakeHistory()
    private val whitelist = FakeWhitelist()
    private val blacklist = FakeBlacklist()
    private val cache = FakeCache()
    private var clock = 1_000_000L
    private val repo = ScanRepository(history, whitelist, blacklist, cache) { clock }
    private var analyzed = 0

    /** The real analyzer (heuristics + ML), with a counter so tests can see when it is skipped. */
    private fun scan(input: String) = runBlocking {
        val blocked = repo.blacklistValues()
        repo.scan(input) { analyzed++; ManualScanAnalyzer.analyze(it, model, blocklist = blocked) }
    }

    @Test
    fun freshUrlIsAnalysedThenSavedToCacheAndHistory() {
        val r = scan("https://www.google.com")
        assertEquals(ScanSource.FRESH, r.source)
        assertEquals(ThreatLevel.SAFE, r.outcome.threat)
        assertEquals(1, analyzed)
        assertEquals(1, cache.rows.size)
        assertEquals(listOf("SAFE"), history.rows.value.map { it.verdict })
        assertEquals("URL", history.rows.value.single().kind)
        assertTrue(history.rows.value.single().mlScore!! in 0.30..0.32)   // ~31%
    }

    @Test
    fun whitelistedHostIsSafeWithoutHeuristicsOrMl() {
        runBlocking { assertTrue(repo.trust("google.com")) }
        val r = scan("https://www.google.com")
        assertEquals(ScanSource.WHITELIST, r.source)
        assertEquals(ThreatLevel.SAFE, r.outcome.threat)
        assertEquals(listOf(ScanRepository.TRUSTED_REASON), r.outcome.reasons.map { it.detail })
        assertTrue("no ML line for a trusted site", r.outcome.infoLines.isEmpty())
        assertEquals("heuristics and ML must be skipped", 0, analyzed)
        assertEquals("still saved to history", 1, history.rows.value.size)
        assertNull(history.rows.value.single().mlScore)
    }

    @Test
    fun whitelistWinsEvenOverADangerousVerdict() {
        runBlocking { repo.trust("185.220.101.45") }
        assertEquals(ThreatLevel.SAFE, scan("http://185.220.101.45/login").outcome.threat)
        assertEquals(0, analyzed)
    }

    @Test
    fun whitelistIsCheckedBeforeCache() {
        assertEquals(ScanSource.FRESH, scan("https://www.google.com").source)   // now cached
        runBlocking { repo.trust("https://www.google.com/anything") }
        assertEquals(ScanSource.WHITELIST, scan("https://www.google.com").source)
    }

    @Test
    fun secondScanOfSameUrlComesFromCache() {
        val first = scan("http://185.220.101.45/login")
        val second = scan("http://185.220.101.45/login")
        assertEquals(ScanSource.FRESH, first.source)
        assertEquals(ScanSource.CACHE, second.source)
        assertEquals(1, analyzed)
        assertEquals(first.outcome.threat, second.outcome.threat)
        assertEquals(ThreatLevel.DANGER, second.outcome.threat)
        assertTrue(second.outcome.reasons.any { it.detail == ScanRepository.CACHE_REASON })
        assertTrue(second.outcome.reasons.any { it.rule == "ip_host" })        // old reasons are kept
        assertTrue(second.outcome.infoLines.single().startsWith("ML:"))
        assertEquals(2, history.rows.value.size)                               // every path saves history
    }

    @Test
    fun cacheKeyIgnoresCaseWhitespaceFragmentAndTrailingSlash() {
        scan("HTTP://185.220.101.45/Login/")
        assertEquals(ScanSource.CACHE, scan(" http://185.220.101.45/login#top ").source)
    }

    @Test
    fun expiredCacheEntryIsAnalysedAgain() {
        scan("https://www.google.com")
        clock += ScanRepository.CACHE_TTL_MS + 1
        assertEquals(ScanSource.FRESH, scan("https://www.google.com").source)
        assertEquals(2, analyzed)
    }

    @Test
    fun textAndPhoneSkipWhitelistAndCacheButAreSaved() {
        runBlocking { repo.trust("google.com") }
        val t = scan("【緊急】您的帳號異常，請立即驗證 http://secure-login.xyz/a")
        val p = scan("+225 07 12 34 56 78")
        assertEquals(ScanType.MESSAGE, t.outcome.kind)
        assertEquals(ScanType.PHONE, p.outcome.kind)
        assertEquals(listOf(ScanSource.FRESH, ScanSource.FRESH), listOf(t.source, p.source))
        assertEquals(2, analyzed)
        assertTrue(cache.rows.isEmpty())
        assertEquals(listOf("TEXT", "PHONE"), history.rows.value.map { it.kind })
    }

    @Test
    fun trustingTwiceKeepsOneRowAndUntrustRemovesIt() {
        runBlocking {
            repo.trust("https://www.Google.com/a"); repo.trust("google.com")
            assertEquals(listOf("google.com"), whitelist.rows.value.map { it.value })
            repo.untrust("google.com")
            assertTrue(whitelist.rows.value.isEmpty())
            assertFalse(repo.trust("   "))
        }
        assertEquals(ScanSource.FRESH, scan("https://www.google.com").source)
    }

    @Test
    fun hostNormalisation() {
        assertEquals("google.com", UrlKeys.host("https://www.Google.com:443/x?y=1#z"))
        assertEquals("google.com", UrlKeys.host("google.com"))
        assertEquals("evil.com", UrlKeys.host("http://google.com@evil.com/"))   // real host is after the @
        assertEquals("evil.com", UrlKeys.host("http://evil.com/?u=google.com"))
        assertNull(UrlKeys.host(""))
    }

    @Test
    fun reasonsSurviveTheJsonRoundTrip() {
        val reasons = listOf(ScanReason("ip_host", "使用 IP 位址", 40, "high"), ScanReason("x", "含 \"引號\" 與 換行\n", 0, "low"))
        assertEquals(reasons, ReasonsJson.decode(ReasonsJson.encode(reasons)))
        assertTrue(ReasonsJson.decode("not json").isEmpty())
    }

    // ---------------------------------------------------------------- blacklist

    @Test
    fun blacklistedUrlIsDangerousWithoutHeuristicsOrMl() {
        assertEquals(ScanSource.FRESH, scan("https://www.google.com").source)   // starts SAFE, and is cached
        analyzed = 0
        runBlocking { assertTrue(repo.block("google.com")) }
        val r = scan("https://www.google.com")
        assertEquals(ScanSource.BLACKLIST, r.source)
        assertEquals(ThreatLevel.DANGER, r.outcome.threat)
        assertEquals(listOf(ScanRepository.BLOCKED_REASON), r.outcome.reasons.map { it.detail })
        assertTrue(r.outcome.infoLines.isEmpty())
        assertEquals("heuristics and ML must be skipped", 0, analyzed)
        assertEquals(listOf("SAFE", "DANGEROUS"), history.rows.value.map { it.verdict })   // saved to history
        assertEquals("DANGEROUS", history.rows.value.last().verdict)
    }

    @Test
    fun blacklistWinsOverWhitelistAndCache() {
        scan("https://www.google.com")                                  // cached
        runBlocking {
            whitelist.insert(WhitelistEntity(value = "google.com", createdAt = 1))   // forced onto both lists
            blacklist.insert(BlacklistEntity(value = "google.com", createdAt = 1))
        }
        assertEquals(ScanSource.BLACKLIST, scan("https://www.google.com").source)
    }

    @Test
    fun blockingMovesTheHostOffTheWhitelistAndTrustingMovesItBack() {
        runBlocking {
            repo.trust("google.com")
            repo.block("https://www.google.com/x")
            assertTrue(whitelist.rows.value.isEmpty())
            assertEquals(listOf("google.com"), blacklist.rows.value.map { it.value })
            repo.trust("google.com")
            assertTrue(blacklist.rows.value.isEmpty())
            assertEquals(listOf("google.com"), whitelist.rows.value.map { it.value })
        }
    }

    @Test
    fun unblockRestoresTheNormalPipeline() {
        runBlocking { repo.block("google.com") }
        assertEquals(ScanSource.BLACKLIST, scan("https://www.google.com").source)
        runBlocking { repo.unblock("google.com") }
        assertTrue(blacklist.rows.value.isEmpty())
        val r = scan("https://www.google.com")
        assertEquals(ScanSource.FRESH, r.source)
        assertEquals(ThreatLevel.SAFE, r.outcome.threat)
    }

    @Test
    fun blockingTwiceKeepsOneRowAndAnEmptyHostIsRejected() {
        runBlocking {
            repo.block("https://www.Evil.com/a"); repo.block("evil.com")
            assertEquals(listOf("evil.com"), blacklist.rows.value.map { it.value })
            assertFalse(repo.block("   "))
        }
    }

    @Test
    fun blockedUrlInsideATextMessageIsFlaggedByTheHeuristicBlocklistRule() {
        runBlocking { repo.block("good-looking-site.com") }
        val r = scan("Please read https://good-looking-site.com/news today")
        assertEquals(ScanType.MESSAGE, r.outcome.kind)
        assertEquals(ScanSource.FRESH, r.source)                         // text always goes to the analyzer
        assertEquals(ThreatLevel.DANGER, r.outcome.threat)
        assertTrue(r.outcome.reasons.any { it.rule == "blocklisted" })
        // the same message without the block is not dangerous
        runBlocking { repo.unblock("good-looking-site.com") }
        assertTrue(scan("Please read https://good-looking-site.com/news today").outcome.threat != ThreatLevel.DANGER)
    }
}
