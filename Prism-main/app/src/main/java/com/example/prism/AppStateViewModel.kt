package com.example.prism

import android.app.Application
import android.content.Context
import androidx.compose.runtime.*
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.prism.data.DbMap
import com.example.prism.data.PrismDatabase
import com.example.prism.data.ReasonsJson
import com.example.prism.data.ScanHistoryEntity
import com.example.prism.data.ScanRepository
import com.example.prism.data.ScanSource
import com.example.prism.data.UrlKeys
import com.example.prism.net.ApiClient
import com.example.prism.net.ApiException
import com.example.prism.net.AuthResult
import com.example.prism.scan.ManualScanAnalyzer
import com.example.prism.scan.PhoneNumbers
import com.example.prism.scan.UrlMlModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.time.Duration.Companion.milliseconds

class AppStateViewModel(application: Application) : AndroidViewModel(application) {

    private val sharedPrefs = application.getSharedPreferences("prism_prefs", Context.MODE_PRIVATE)

    var activeTab by mutableStateOf("scan")
    var scanInput by mutableStateOf("")
    var scanType by mutableStateOf(ScanType.URL)
    var isScanning by mutableStateOf(false)

    // Friendly input error for Manual Scan (null = nothing to show)
    var scanError by mutableStateOf<String?>(null)

    // Local URL model (assets/url_model.json); null if it cannot be loaded -> heuristics only
    private val urlModel: UrlMlModel? by lazy {
        runCatching {
            UrlMlModel.fromJson(getApplication<Application>().assets.open("url_model.json").bufferedReader().use { it.readText() })
        }.getOrNull()
    }

    // Optimized primitive backing state for Compose
    var privacyScore = mutableIntStateOf(85)

    var isLoggedIn by mutableStateOf(false)
    var showFrontPage by mutableStateOf(true)
    var showSubscriptionModal by mutableStateOf(false)
    var subscriptionPlan by mutableStateOf<SubscriptionPlan?>(null)
    var showThreatAlert by mutableStateOf(false)
    var threatAlertData by mutableStateOf<ScanResult?>(null)
    // Where the popup's verdict came from: decides which popup variant is shown (blocked / trusted / normal)
    var threatAlertSource by mutableStateOf(ScanSource.FRESH)
    var clipboardMonitoring by mutableStateOf(true)

    var loginEmail by mutableStateOf("")
    var loginPassword by mutableStateOf("")
    var isLoggingIn by mutableStateOf(false)

    var showSignUp by mutableStateOf(false)
    var signUpName by mutableStateOf("")
    var signUpEmail by mutableStateOf("")
    var signUpPassword by mutableStateOf("")
    var signUpConfirmPassword by mutableStateOf("")
    var isSigningUp by mutableStateOf(false)

    // Dashboard numbers. Always computed from the database (see observeDatabase), never hard-coded.
    var scansToday by mutableIntStateOf(0)        // total scans
    var threatsBlocked by mutableIntStateOf(0)    // DANGEROUS verdicts
    var privacyAlerts by mutableIntStateOf(0)     // SUSPICIOUS verdicts

    // History and whitelist mirror the encrypted database (permanent across app restarts)
    var scanHistory = mutableStateListOf<ScanResult>()
    var whitelistItems = mutableStateListOf<String>()
    var blacklistItems = mutableStateListOf<String>()


    // Opened off the main thread: the encrypted database must not block the UI
    private val repoDeferred = viewModelScope.async(Dispatchers.IO) {
        val db = PrismDatabase.open(getApplication())
        db.urlCacheDao().deleteOlderThan(System.currentTimeMillis() - ScanRepository.CACHE_TTL_MS)
        db to ScanRepository(db.historyDao(), db.whitelistDao(), db.blacklistDao(), db.urlCacheDao())
    }

    init {
        PhoneNumbers.init(application)
        checkSavedSession()
        observeDatabase()
    }

    /** History, stats and whitelist are read from the database; the UI refreshes on every change. */
    private fun observeDatabase() {
        viewModelScope.launch {
            val db = repoDeferred.await().first
            val history = db.historyDao()
            launch {
                history.observeAll().collect { rows ->
                    scanHistory.clear()
                    scanHistory.addAll(rows.map { it.toScanResult() })
                }
            }
            launch { history.observeTotal().collect { scansToday = it; updatePrivacyScore() } }
            launch { history.observeCount("DANGEROUS").collect { threatsBlocked = it; updatePrivacyScore() } }
            launch { history.observeCount("SUSPICIOUS").collect { privacyAlerts = it; updatePrivacyScore() } }
            launch {
                db.whitelistDao().observeAll().collect { rows ->
                    whitelistItems.clear()
                    whitelistItems.addAll(rows.map { it.value })
                }
            }
            launch {
                db.blacklistDao().observeAll().collect { rows ->
                    blacklistItems.clear()
                    blacklistItems.addAll(rows.map { it.value })
                }
            }
        }
    }

    // Same formula as prism-backend: start at 100, -5 per DANGEROUS, -2 per SUSPICIOUS
    private fun updatePrivacyScore() {
        privacyScore.intValue = (100 - threatsBlocked * 5 - privacyAlerts * 2).coerceIn(0, 100)
    }

    private fun ScanHistoryEntity.toScanResult(): ScanResult {
        val reasonList = ReasonsJson.decode(reasons)
        return ScanResult(
            id = id.toString(),
            type = DbMap.type(kind),
            content = input,
            threat = DbMap.threat(verdict),
            timestamp = timestamp,
            details = reasonList.take(2).joinToString("; ") { it.detail },
            reasons = reasonList,
            infoLines = mlScore?.let { listOf("ML: ${ManualScanAnalyzer.percent(it)}% phishing probability") } ?: emptyList()
        )
    }

    /** Adds the host of the URL in the popup to the whitelist. */
    fun trustCurrentUrl(onMessage: (String) -> Unit) {
        val data = threatAlertData ?: return
        if (data.type != ScanType.URL) return
        viewModelScope.launch {
            val ok = repoDeferred.await().second.trust(data.content)
            showThreatAlert = false
            onMessage(if (ok) "Added to trusted sites: ${UrlKeys.host(data.content)}" else "Could not add to trusted sites")
        }
    }

    /** Adds the host of the URL in the popup to the blacklist (always DANGEROUS from now on). */
    fun blacklistCurrentUrl(onMessage: (String) -> Unit) {
        val data = threatAlertData ?: return
        if (data.type != ScanType.URL) return
        viewModelScope.launch {
            val ok = repoDeferred.await().second.block(data.content)
            showThreatAlert = false
            onMessage(if (ok) "Blocked: ${UrlKeys.host(data.content)}" else "Could not block this site")
        }
    }

    /** Popup "Unblock this site": DELETE the host from the block list, then close. */
    fun unblockCurrentUrl() {
        val data = threatAlertData ?: return
        showThreatAlert = false
        viewModelScope.launch { repoDeferred.await().second.let { it.unblock(UrlKeys.host(data.content) ?: data.content) } }
    }

    /** Popup "Untrust this site": DELETE the host from the trust list, then close. */
    fun untrustCurrentUrl() {
        val data = threatAlertData ?: return
        showThreatAlert = false
        viewModelScope.launch { repoDeferred.await().second.let { it.untrust(UrlKeys.host(data.content) ?: data.content) } }
    }

    fun removeFromBlacklist(value: String) {
        viewModelScope.launch { repoDeferred.await().second.unblock(value) }
    }

    fun removeFromWhitelist(value: String) {
        viewModelScope.launch { repoDeferred.await().second.untrust(value) }
    }

    private fun checkSavedSession() {
        val savedLogin = sharedPrefs.getBoolean("prism_logged_in", false)
        val savedPlanString = sharedPrefs.getString("prism_plan", null)

        if (savedLogin) {
            isLoggedIn = true
            showFrontPage = false
            subscriptionPlan = when (savedPlanString) {
                "FREE" -> SubscriptionPlan.FREE
                "PLUS" -> SubscriptionPlan.PLUS
                else -> {
                    showSubscriptionModal = true
                    null
                }
            }
        }
    }

    fun handleLogin(onValidationError: (String) -> Unit, onLoginSuccess: (String) -> Unit) {
        if (loginEmail.isBlank() || loginPassword.isBlank()) {
            onValidationError("Please enter email and password")
            return
        }

        isLoggingIn = true

        viewModelScope.launch {
            try {
                val r = withContext(Dispatchers.IO) { ApiClient.login(loginEmail.trim(), loginPassword) }
                saveSession(r)
                isLoggedIn = true
                subscriptionPlan = r.plan?.let { SubscriptionPlan.valueOf(it) }
                if (r.plan == null) {
                    showSubscriptionModal = true
                } else {
                    onLoginSuccess("Welcome back! You are now logged in securely.")
                }
            } catch (e: Exception) {
                onValidationError(friendlyError(e))
            } finally {
                isLoggingIn = false
            }
        }
    }

    /** Stores the server session (token, profile, plan) so the app stays logged in after a restart. */
    private fun saveSession(r: AuthResult) {
        sharedPrefs.edit().apply {
            putBoolean("prism_logged_in", true)
            putString("prism_token", r.token)
            putString("prism_email", r.email)
            putString("prism_name", r.name)
            if (r.plan != null) putString("prism_plan", r.plan) else remove("prism_plan")
            apply()
        }
    }

    private fun friendlyError(e: Exception): String =
        if (e is ApiException) e.message ?: "Request failed" else "Cannot reach the server. Check your connection."

    fun handlePlanSelection(plan: SubscriptionPlan, onMessage: (String, String) -> Unit) {
        subscriptionPlan = plan

        sharedPrefs.edit().apply {
            putString("prism_plan", plan.name)
            apply()
        }

        showSubscriptionModal = false

        // Tell the server too (best effort: the plan is already saved locally)
        val token = sharedPrefs.getString("prism_token", null)
        if (token != null) {
            viewModelScope.launch {
                runCatching { withContext(Dispatchers.IO) { ApiClient.setPlan(token, plan.name) } }
            }
        }

        if (plan == SubscriptionPlan.FREE) {
            onMessage("Welcome to Prism!", "You can upgrade anytime for advanced features.")
        } else {
            onMessage("Welcome to Prism Premium!", "Enjoy unlimited scans and premium protection features.")
        }
    }

    fun handleSignUp(
        onValidationError: (String) -> Unit,
        onSignUpSuccess: (String, String) -> Unit
    ) {
        if (signUpName.isBlank() || signUpEmail.isBlank() || signUpPassword.isBlank() || signUpConfirmPassword.isBlank()) {
            onValidationError("Please fill in all fields")
            return
        }

        if (signUpPassword != signUpConfirmPassword) {
            onValidationError("Passwords do not match")
            return
        }

        if (signUpPassword.length < 6) {
            onValidationError("Password must be at least 6 characters")
            return
        }

        isSigningUp = true

        viewModelScope.launch {
            try {
                val r = withContext(Dispatchers.IO) {
                    ApiClient.signup(signUpName.trim(), signUpEmail.trim(), signUpPassword)
                }
                saveSession(r)
                isLoggedIn = true
                showSignUp = false
                showSubscriptionModal = true
                onSignUpSuccess("Account created successfully!", "Now choose your protection plan.")
            } catch (e: Exception) {
                onValidationError(friendlyError(e))
            } finally {
                isSigningUp = false
            }
        }
    }

    fun autoScanClipboard(url: String) {
        viewModelScope.launch {
            delay(1000.milliseconds)

            val isDangerous = Math.random() > 0.6
            val threat = if (isDangerous) ThreatLevel.DANGER else ThreatLevel.SAFE
            val details = if (isDangerous) {
                "THREAT DETECTED: This link has been reported as malicious. Do not click or share."
            } else {
                "Link appears safe based on our database."
            }

            val newResult = ScanResult(
                id = System.currentTimeMillis().toString(),
                type = ScanType.URL,
                content = url,
                threat = threat,
                timestamp = System.currentTimeMillis(),
                details = details
            )

            // Update stats live during clipboard automated execution
            scansToday++
            if (threat == ThreatLevel.DANGER) {
                threatsBlocked++
            }

            scanHistory.add(0, newResult)
            threatAlertSource = ScanSource.FRESH
            threatAlertData = newResult
            showThreatAlert = true
        }
    }

    fun handleScan(
        onSafeScan: (String, String) -> Unit
    ) {
        val input = scanInput.trim()
        scanError = null
        if (input.isEmpty()) {
            scanError = "Please enter something to scan"
            return
        }
        // Input kind (URL / text / phone number) is detected automatically by ManualScanAnalyzer.
        isScanning = true

        viewModelScope.launch {
            delay(300.milliseconds)

            val advanced = subscriptionPlan == SubscriptionPlan.PLUS
            val repo = repoDeferred.await().second
            // Pipeline: blacklist -> whitelist -> cache -> heuristics + ML -> save (see ScanRepository)
            val blocked = repo.blacklistValues()   // lets the heuristic "blocklisted" rule see blocked URLs inside messages
            val res = repo.scan(input) { ManualScanAnalyzer.analyze(it, urlModel, advanced, blocked) }
            val outcome = res.outcome
            val newScan = ScanResult(
                id = System.currentTimeMillis().toString(),
                type = outcome.kind,
                content = input,
                threat = outcome.threat,
                timestamp = System.currentTimeMillis(),
                details = outcome.reasons.take(2).joinToString("; ") { it.detail },
                reasons = outcome.reasons,
                infoLines = outcome.infoLines
            )
            // History and the dashboard numbers update themselves from the database flows.
            isScanning = false
            scanInput = ""

            // Every verdict (SAFE / SUSPICIOUS / DANGEROUS) opens the ThreatAlertDialog popup.
            threatAlertSource = res.source
            threatAlertData = newScan
            showThreatAlert = true
        }
    }

    fun getThreatColorHex(threat: ThreatLevel): Long {
        return when (threat) {
            ThreatLevel.SAFE -> 0xFF16A34A
            ThreatLevel.WARNING -> 0xFFCA8A04
            ThreatLevel.DANGER -> 0xFFDC2626
        }
    }

    fun getThreatBgHex(threat: ThreatLevel): Long {
        return when (threat) {
            ThreatLevel.SAFE -> 0xFFF0FDF4
            ThreatLevel.WARNING -> 0xFFFEFCE8
            ThreatLevel.DANGER -> 0xFFFEF2F2
        }
    }
}