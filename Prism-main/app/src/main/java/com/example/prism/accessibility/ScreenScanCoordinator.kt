package com.example.prism.accessibility

import android.content.Context
import android.util.Log
import com.example.prism.ScanReason
import com.example.prism.ThreatLevel
import com.example.prism.data.PrismDatabase
import com.example.prism.data.RepoScanResult
import com.example.prism.data.ScanRepository
import com.example.prism.data.ScanSource
import com.example.prism.data.UrlKeys
import com.example.prism.scan.ManualScanAnalyzer
import com.example.prism.scan.PhoneNumbers
import com.example.prism.scan.UrlMlModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Bridge between the accessibility service and the app's existing detection stack.
 *
 * Screen URLs go through exactly the same pipeline as Manual Scan:
 * `blacklist -> whitelist -> cache -> heuristics + ML -> save to Room`.
 * That means a link caught on screen appears in History, updates the dashboard counters, and
 * shares the same trust/block lists as the manual scanner.
 *
 * If the encrypted database or the ML asset cannot be opened, [UrlHeuristics] keeps the shield
 * working instead of failing open.
 */
class ScreenScanCoordinator(private val context: Context) {

    private val initLock = Mutex()

    @Volatile
    private var repository: ScanRepository? = null

    @Volatile
    private var model: UrlMlModel? = null

    @Volatile
    private var ready = false

    suspend fun scan(rawUrl: String): UrlVerdict {
        ensureReady()
        val repo = repository ?: return fallback(rawUrl)

        val advanced = context
            .getSharedPreferences("prism_prefs", Context.MODE_PRIVATE)
            .getString("prism_plan", null) == "PLUS"

        val result = runCatching {
            withContext(Dispatchers.IO) {
                val blocked = repo.blacklistValues()
                repo.scan(rawUrl) { text ->
                    val outcome = ManualScanAnalyzer.analyze(text, model, advanced, blocked)
                    outcome.copy(
                        reasons = outcome.reasons + ScanReason(
                            rule = "screen_scan",
                            detail = "Detected automatically while watching the screen",
                            points = 0,
                            severity = "low"
                        ),
                        infoLines = outcome.infoLines + "Source: screen monitoring"
                    )
                }
            }
        }.onFailure { Log.w(TAG, "Screen scan failed, using local heuristics", it) }
            .getOrNull()

        return result?.toVerdict(rawUrl) ?: fallback(rawUrl)
    }

    /** Adds the URL's host to the encrypted whitelist (manual override loop). */
    suspend fun trust(rawUrl: String): Boolean {
        ensureReady()
        val repo = repository ?: return false
        return runCatching {
            withContext(Dispatchers.IO) { repo.trust(rawUrl) }
        }.onFailure { Log.w(TAG, "Could not trust $rawUrl", it) }
            .getOrDefault(false)
    }

    // ---------------------------------------------------------------------------------------

    private suspend fun ensureReady() {
        if (ready) return
        initLock.withLock {
            if (ready) return
            withContext(Dispatchers.IO) {
                runCatching {
                    // Merge glue (2.0): the service can start without the UI, and the 2.0 analyzer needs
                    // libphonenumber initialised. Idempotent; same call as AppStateViewModel.
                    PhoneNumbers.init(context)
                    val db = PrismDatabase.open(context)
                    repository = ScanRepository(
                        db.historyDao(),
                        db.whitelistDao(),
                        db.blacklistDao(),
                        db.urlCacheDao()
                    )
                    model = runCatching {
                        UrlMlModel.fromJson(
                            context.assets.open("url_model.json").bufferedReader().use { it.readText() }
                        )
                    }.getOrNull()
                    ready = true
                    Log.i(TAG, "Screen scanner ready (ML model: ${model != null})")
                }.onFailure {
                    Log.e(TAG, "Could not open the encrypted database; using heuristics only", it)
                }
            }
        }
    }

    private fun RepoScanResult.toVerdict(rawUrl: String): UrlVerdict {
        val host = UrlKeys.host(rawUrl)

        // Two independent engines run for screen links: Livio's rule+ML scanner and the shield's
        // heuristics (broader brand list: Discord, Steam, Taiwanese banks, ...). The more
        // dangerous verdict wins, so neither engine can silently downgrade the other.
        val local = UrlHeuristics.analyze(rawUrl)

        val scannerSignals = outcome.reasons
            .filter { it.rule != "no_issues" && it.rule != "screen_scan" }
            .map { RiskSignal(it.rule, it.points, it.detail) }
        val signals = (scannerSignals + local.signals)
            .distinctBy { it.label }
            .sortedByDescending { it.weight }

        val level = if (local.level.ordinal > outcome.threat.ordinal) local.level else outcome.threat
        val scannerScore = when (outcome.threat) {
            ThreatLevel.DANGER -> maxOf(scannerSignals.sumOf { it.weight }, 80)
            ThreatLevel.WARNING -> maxOf(scannerSignals.sumOf { it.weight }, 45)
            ThreatLevel.SAFE -> minOf(scannerSignals.sumOf { it.weight }, 20)
        }
        val score = maxOf(scannerScore, local.score).coerceIn(0, 100)

        val scannerReason = outcome.reasons
            .filter { it.rule != "screen_scan" }
            .maxByOrNull { it.points }
            ?.detail
            ?: "No threats detected"
        val reason = if (local.level.ordinal > outcome.threat.ordinal) local.summary else scannerReason

        return UrlVerdict(
            url = rawUrl,
            host = host,
            domain = host?.let { UrlTextParser.registrableDomain(it) },
            level = level,
            score = score,
            reason = reason,
            signals = signals,
            source = when (source) {
                ScanSource.WHITELIST -> VerdictSource.WHITELIST
                ScanSource.BLACKLIST -> VerdictSource.BLACKLIST
                ScanSource.CACHE -> VerdictSource.CACHE
                ScanSource.FRESH -> VerdictSource.LOCAL
            }
        )
    }

    private fun fallback(rawUrl: String): UrlVerdict {
        val report = UrlHeuristics.analyze(rawUrl)
        return UrlVerdict(
            url = report.url,
            host = report.host,
            domain = report.domain,
            level = report.level,
            score = report.score,
            reason = report.summary,
            signals = report.signals,
            source = VerdictSource.LOCAL
        )
    }

    private companion object {
        const val TAG = "PrismShield"
    }
}
