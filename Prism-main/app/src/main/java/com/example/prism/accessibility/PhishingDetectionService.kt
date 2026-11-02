package com.example.prism.accessibility

import android.accessibilityservice.AccessibilityService
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.widget.Toast
import com.example.prism.ThreatLevel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Prism Screen Shield - the accessibility layer of the merged app.
 *
 * Screen URLs are handed to [ScreenScanCoordinator], which runs the **same** pipeline as Manual
 * Scan (blacklist -> whitelist -> encrypted cache -> heuristics + ML, then saves to Room). So a
 * link caught on screen shows up in History, moves the dashboard counters, and respects the same
 * trust/block lists.
 *
 * Decisions:
 *  - DANGER  -> full-screen blocking shield; a tap also cancels the navigation.
 *  - WARNING -> caution shield in a browser, quiet toast in a chat until the link is tapped.
 *  - SAFE    -> one toast per domain per 10 minutes, nothing else.
 *  - "I trust this site" writes the host to the encrypted whitelist through the repository.
 *
 * Performance: events are throttled, tree walks are node-capped, analysis runs on
 * [Dispatchers.Default]/IO, and only the overlay is touched on the main thread.
 */
class PhishingDetectionService : AccessibilityService() {

    companion object {
        private const val TAG = "PrismShield"

        private const val WINDOW_SCAN_INTERVAL_MS = 350L

        /**
         * A URL already handled from the screen is not re-analysed (and therefore not written to
         * History again) for this long. Interactive clicks bypass it. Five minutes keeps the
         * encrypted history readable while still catching links that change after a blacklist sync.
         */
        private const val URL_DEDUPE_TTL_MS = 5 * 60_000L
        private const val SAFE_TOAST_INTERVAL_MS = 10 * 60_000L
        private const val AUTO_BACK_DELAY_MS = 300L

        private const val MAX_URLS_PER_WINDOW = 5
        private const val MAX_CLICK_URLS = 2
        private const val RECENT_URL_CAPACITY = 128

        @Volatile
        private var connected = false

        /** True while the service is bound and able to shield the screen. */
        fun isRunning(): Boolean = connected
    }

    private var serviceScope = newScope()
    private val mainHandler = Handler(Looper.getMainLooper())

    private var coordinator: ScreenScanCoordinator? = null
    private var settings: ScreenShieldSettings? = null
    private var shield: ThreatShieldController? = null

    private var lastWindowScanAt = 0L
    private var autoBackPendingForUrl: String? = null
    private var autoBackDoneForUrl: String? = null

    /** Insertion-ordered LRU of recently handled URLs. */
    private val recentUrls = LinkedHashMap<String, Long>(64, 0.75f, true)
    private val continuedUrls = HashSet<String>()
    private val safeToastAt = HashMap<String, Long>()
    private val warningToastAt = HashMap<String, Long>()

    // ---------------------------------------------------------------------------------------
    // Lifecycle
    // ---------------------------------------------------------------------------------------

    override fun onServiceConnected() {
        super.onServiceConnected()

        serviceScope.cancel()
        serviceScope = newScope()

        val app = applicationContext
        coordinator = ScreenScanCoordinator(app)
        settings = ScreenShieldSettings(app)
        if (shield == null) shield = ThreatShieldController(this)

        connected = true
        Log.i(TAG, "Prism screen shield connected")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        val currentEvent = event ?: return
        try {
            handleEvent(currentEvent)
        } catch (throwable: Throwable) {
            Log.w(TAG, "Skipped an accessibility event", throwable)
        }
    }

    override fun onInterrupt() {
        shield?.dismiss()
    }

    override fun onUnbind(intent: Intent?): Boolean {
        connected = false
        shield?.dismiss()
        Log.i(TAG, "Prism screen shield unbound")
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        connected = false
        serviceScope.cancel()
        shield?.destroy()
        shield = null
        super.onDestroy()
    }

    // ---------------------------------------------------------------------------------------
    // Event handling
    // ---------------------------------------------------------------------------------------

    private fun handleEvent(event: AccessibilityEvent) {
        val sourcePackage = event.packageName?.toString() ?: return

        // Never analyse our own overlay (would be an infinite feedback loop).
        if (sourcePackage == packageName) return
        if (sourcePackage in MonitoredApps.IGNORED) return
        if (shield?.isShowing == true) return

        val shieldSettings = settings ?: return
        if (!shieldSettings.monitorAllApps && !MonitoredApps.isMonitored(sourcePackage)) return

        when (event.eventType) {
            AccessibilityEvent.TYPE_VIEW_CLICKED -> handleClick(event, sourcePackage)

            AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED,
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED,
            AccessibilityEvent.TYPE_VIEW_SCROLLED,
            AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED,
            AccessibilityEvent.TYPE_VIEW_FOCUSED -> scanCurrentWindow(sourcePackage)

            else -> Unit
        }
    }

    private fun handleClick(event: AccessibilityEvent, sourcePackage: String) {
        val urls = UrlExtractor.aroundNode(event.source)
        if (urls.isEmpty()) return
        val contextText = event.text?.joinToString(" ")?.takeIf { it.isNotBlank() }
        urls.take(MAX_CLICK_URLS).forEach { url ->
            enqueueAnalysis(url, sourcePackage, contextText, interactive = true)
        }
    }

    private fun scanCurrentWindow(sourcePackage: String) {
        val now = SystemClock.uptimeMillis()
        if (now - lastWindowScanAt < WINDOW_SCAN_INTERVAL_MS) return
        lastWindowScanAt = now

        val root = rootInActiveWindow ?: return
        val scan = UrlExtractor.scanWindow(root, addressBarOnly = MonitoredApps.isBrowser(sourcePackage))
        if (scan.urls.isEmpty()) return

        scan.urls.take(MAX_URLS_PER_WINDOW).forEach { url ->
            enqueueAnalysis(url, sourcePackage, scan.contextText, interactive = false)
        }
    }

    private fun enqueueAnalysis(
        url: String,
        sourcePackage: String,
        contextText: String?,
        interactive: Boolean
    ) {
        val cacheKey = UrlTextParser.cacheKey(url)
        if (cacheKey.length < 5) return

        val now = SystemClock.elapsedRealtime()
        synchronized(recentUrls) {
            val lastSeen = recentUrls[cacheKey]
            if (!interactive && lastSeen != null && now - lastSeen < URL_DEDUPE_TTL_MS) return
            recentUrls[cacheKey] = now
            if (recentUrls.size > RECENT_URL_CAPACITY) {
                recentUrls.keys.firstOrNull()?.let(recentUrls::remove)
            }
        }

        val scanCoordinator = coordinator ?: return
        serviceScope.launch {
            val verdict = runCatching { scanCoordinator.scan(url) }.getOrNull() ?: return@launch
            withContext(Dispatchers.Main) {
                onVerdict(verdict, sourcePackage, interactive)
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Decision execution
    // ---------------------------------------------------------------------------------------

    private fun onVerdict(verdict: UrlVerdict, sourcePackage: String, interactive: Boolean) {
        Log.i(TAG, "Screen verdict ${verdict.level} (${verdict.score}): ${verdict.url}")

        when (verdict.level) {
            ThreatLevel.SAFE -> showSafeToast(verdict)

            ThreatLevel.WARNING, ThreatLevel.DANGER -> {
                val cacheKey = UrlTextParser.cacheKey(verdict.url)
                val alreadyContinued = synchronized(continuedUrls) { continuedUrls.contains(cacheKey) }
                val shouldShow = !alreadyContinued && shouldPresentShield(verdict, sourcePackage, interactive)

                if (!alreadyContinued && !shouldShow) {
                    // A suspicious link sitting in a chat stays quiet until it is tapped.
                    showWarningToast(verdict, sourcePackage)
                }
                if (shouldShow) {
                    presentShield(verdict, sourcePackage, interactive)
                }
            }
        }
    }

    private fun shouldPresentShield(
        verdict: UrlVerdict,
        sourcePackage: String,
        interactive: Boolean
    ): Boolean = when (verdict.level) {
        ThreatLevel.DANGER -> true
        ThreatLevel.WARNING -> interactive || MonitoredApps.isBrowser(sourcePackage)
        ThreatLevel.SAFE -> false
    }

    private fun presentShield(
        verdict: UrlVerdict,
        sourcePackage: String,
        interactive: Boolean
    ): Boolean {
        val shieldController = shield ?: return false
        val shieldSettings = settings ?: return false
        val domain = verdict.domain ?: verdict.host

        autoBackPendingForUrl = null
        autoBackDoneForUrl = null

        if (!shieldSettings.overlayEnabled) {
            Toast.makeText(
                this,
                "Prism: suspicious link detected (${domain ?: verdict.url})",
                Toast.LENGTH_LONG
            ).show()
            return false
        }

        shieldController.show(
            verdict = verdict,
            sourceLabel = "Detected in ${MonitoredApps.displayName(sourcePackage)}",
            actions = ShieldActions(
                onLeave = { leavePage(verdict.url) },
                onContinue = {
                    synchronized(continuedUrls) { continuedUrls.add(UrlTextParser.cacheKey(verdict.url)) }
                    autoBackPendingForUrl = null
                    autoBackDoneForUrl = null
                    Toast.makeText(
                        this,
                        "Continuing to ${domain ?: "this site"} - stay alert.",
                        Toast.LENGTH_SHORT
                    ).show()
                },
                onTrust = {
                    synchronized(continuedUrls) { continuedUrls.add(UrlTextParser.cacheKey(verdict.url)) }
                    autoBackPendingForUrl = null
                    autoBackDoneForUrl = null
                    val target = verdict.url
                    serviceScope.launch {
                        val ok = runCatching { coordinator?.trust(target) ?: false }.getOrDefault(false)
                        withContext(Dispatchers.Main) {
                            Toast.makeText(
                                this@PhishingDetectionService,
                                if (ok) {
                                    "${domain ?: target} added to your allowlist"
                                } else {
                                    "Could not trust this site"
                                },
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                    }
                }
            )
        )

        // For a click on a dangerous link, cancel the navigation that is already in flight.
        if (verdict.level == ThreatLevel.DANGER && interactive) {
            val targetUrl = verdict.url
            autoBackPendingForUrl = targetUrl
            mainHandler.postDelayed({
                if (autoBackPendingForUrl != targetUrl) return@postDelayed
                autoBackPendingForUrl = null
                if (shield?.isShowing == true) {
                    performGlobalAction(GLOBAL_ACTION_BACK)
                    autoBackDoneForUrl = targetUrl
                }
            }, AUTO_BACK_DELAY_MS)
        }
        return true
    }

    private fun leavePage(url: String) {
        val alreadyCancelled = autoBackDoneForUrl == url
        autoBackPendingForUrl = null
        autoBackDoneForUrl = null
        if (!alreadyCancelled) performGlobalAction(GLOBAL_ACTION_BACK)
    }

    private fun showSafeToast(verdict: UrlVerdict) {
        val domain = verdict.domain ?: verdict.host ?: return
        if (!reserveToastSlot(safeToastAt, domain)) return
        Toast.makeText(this, "Prism: $domain looks safe", Toast.LENGTH_SHORT).show()
    }

    private fun showWarningToast(verdict: UrlVerdict, sourcePackage: String) {
        val domain = verdict.domain ?: verdict.host ?: return
        if (!reserveToastSlot(warningToastAt, domain)) return
        Toast.makeText(
            this,
            "Prism: suspicious link in ${MonitoredApps.displayName(sourcePackage)} - check before tapping",
            Toast.LENGTH_SHORT
        ).show()
    }

    /** True when this domain has not produced a toast recently, so we never spam the user. */
    private fun reserveToastSlot(tracker: MutableMap<String, Long>, key: String): Boolean {
        val now = SystemClock.elapsedRealtime()
        synchronized(tracker) {
            val last = tracker[key]
            if (last != null && now - last < SAFE_TOAST_INTERVAL_MS) return false
            tracker[key] = now
            return true
        }
    }

    private fun newScope(): CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
}
